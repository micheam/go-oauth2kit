package oauth2kit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/oauth2"
)

// Manager handles OAuth2 authentication flows with automatic token management.
// It provides a high-level interface for OAuth2 operations including token
// acquisition, persistence, and refresh.
type Manager struct {
	// Config contains all OAuth2 configuration settings.
	Config Config

	// LoggerRepository provides logging capabilities.
	// If nil, no logging is performed.
	LoggerRepository

	// Writer specifies the output writer for informational messages.
	// If nil, os.Stdout is used.
	Writer io.Writer
}

const (
	defaultLocalAddr  = ":15440"
	defaultServerPath = "/callback"
)

func (m *Manager) oauth2ConfigOAuth2() *oauth2.Config {
	return m.Config.oauth2Config()
}

func (c *Manager) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	return c.oauth2ConfigOAuth2().TokenSource(ctx, t)
}

func (m *Manager) NewOAuth2Client(ctx context.Context) (*http.Client, error) {
	token, err := m.GetToken(ctx)
	if err != nil {
		return nil, err
	}
	ts := m.TokenSource(ctx, token)

	// Force token validation and refresh if expired
	validToken, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("validate/refresh token: %w", err)
	}

	// Save refreshed token if it changed
	if validToken.AccessToken != token.AccessToken {
		if err := store(m.Config.TokenFile, validToken); err != nil {
			// Log warning but don't fail the request
			logger := m.LoggerFromContext(ctx)
			logger.Warn("Failed to save refreshed token: " + err.Error())
		}
	}

	return oauth2.NewClient(ctx, ts), nil
}

func (m *Manager) GetWriter() io.Writer {
	if m.Writer != nil {
		return m.Writer
	}
	return os.Stdout
}

func (m *Manager) GetToken(ctx context.Context) (*oauth2.Token, error) {
	if m.LoggerRepository == nil {
		m.LoggerRepository = &StandardLoggerRepository{}
	}
	logger := m.LoggerFromContext(ctx)

	cfg := m.Config
	tokenFile := cfg.TokenFile

	_, err := os.Stat(tokenFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// Not Yet Create, nor Load any Token => Need to Newly Authenticate.
	if err != nil && os.IsNotExist(err) {

		localAddr := defaultLocalAddr
		if addr := cfg.LocalAddr; addr != "" {
			localAddr = addr
		}
		// Generate PKCE verifier - oauth2 package now handles this internally
		verifier := oauth2.GenerateVerifier()

		// Create authorization URL with PKCE parameters using S256ChallengeOption
		authURL := m.oauth2ConfigOAuth2().AuthCodeURL(
			"state-token",
			oauth2.AccessTypeOffline,
			oauth2.S256ChallengeOption(verifier),
		)

		// Channel to receive authorization code
		codeChan := make(chan string)
		errorChan := make(chan error)

		// Start local server to receive callback
		server := &http.Server{Addr: localAddr}
		path := cfg.ServerPath
		if path == "" {
			path = defaultServerPath
		}
		http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			code := r.URL.Query().Get("code")
			if code == "" {
				errorChan <- fmt.Errorf("no authorization code received")
				fmt.Fprintf(w, "Error: No authorization code received")
				return
			}

			codeChan <- code
			html := `<html>
			  <body>
				<h1>Authentication Successful!</h1>
				<p>You can close this window and return to the terminal.</p>
			  </body>
			  </html>`
			fmt.Fprint(w, html)
		})

		// Start server in goroutine
		go func() {
			if err := server.ListenAndServe(); err != http.ErrServerClosed {
				errorChan <- err
			}
		}()

		// Open browser to authorization URL
		fmt.Println("Opening browser for authentication...")
		if err := openURL(authURL); err != nil {
			logger.Warn("Failed to open browser: " + err.Error())
			fmt.Fprintf(m.GetWriter(), "Please open the following URL in your browser:\n%s\n", authURL)
		}

		// Wait for authorization code
		var authCode string
		select {
		case authCode = <-codeChan:
			fmt.Fprintln(m.GetWriter(), "\n✓ Authorization code received")
		case err := <-errorChan:
			logger.Error("Error during authorization: " + err.Error())
		case <-time.After(5 * time.Minute):
			logger.Error("Timeout waiting for authorization code")
		}

		// Shutdown the server
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("Server shutdown error: " + err.Error())
		}

		// Exchange authorization code for token with PKCE verifier
		fmt.Fprintln(m.GetWriter(), "Exchanging authorization code for token...")
		token, err := m.oauth2ConfigOAuth2().Exchange(ctx, authCode, oauth2.VerifierOption(verifier))
		if err != nil {
			return nil, fmt.Errorf("token exchange: %w", err)
		}

		// Save token to file
		if err := store(tokenFile, token); err != nil {
			return nil, fmt.Errorf("store token: %w", err)
		}
		logger.Debug("✓ Token saved to file: " + tokenFile)
		return token, nil
	}

	// Load existing token from file
	logger.Debug("Loading token from file: " + tokenFile)
	token, err := load(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("load token from file: %w", err)
	}
	return token, nil
}

// ----------------------------------------------------------------------------
// Interfaces
// ----------------------------------------------------------------------------

type LoggerRepository interface {
	LoggerFromContext(ctx context.Context) *slog.Logger
	ContextWithLogger(ctx context.Context, logger *slog.Logger) context.Context
}

type StandardLoggerRepository struct{}

func (r *StandardLoggerRepository) LoggerFromContext(ctx context.Context) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func (r *StandardLoggerRepository) ContextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return ctx // No-op for standard implementation
}

// ----------------------------------------------------------------------------

// Config holds configuration options for the OAuth2 manager.
// All OAuth2-related settings are contained within this structure.
type Config struct {
	// ClientID is the OAuth2 client identifier issued by the provider.
	ClientID string

	// ClientSecret is the OAuth2 client secret issued by the provider.
	ClientSecret string

	// Scopes specifies the list of requested permission scopes.
	Scopes []string

	// Endpoint contains the provider's OAuth2 endpoint URLs.
	Endpoint oauth2.Endpoint

	// ServerPath is the path for the local callback server.
	// Default: "/callback"
	ServerPath string

	// LocalAddr is the address for the local callback server.
	// Default: ":15440"
	LocalAddr string

	// TokenFile is the path where tokens are persisted.
	// Default: "token.json"
	TokenFile string
}

func (c *Config) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     c.Endpoint,
		RedirectURL:  c.buildRedirectURL(),
		Scopes:       c.Scopes,
	}
}

func (c *Config) buildRedirectURL() string {
	localAddr := c.LocalAddr
	if localAddr == "" {
		localAddr = defaultLocalAddr
	}
	return fmt.Sprintf("http://localhost%s/callback", localAddr)
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

func openURL(url string) error {
	switch os := runtime.GOOS; os {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default: // "linux", "freebsd", "openbsd", "netbsd"
		return exec.Command("xdg-open", url).Start()
	}
}

func store(fileName string, token *oauth2.Token) error {
	f, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(token)
}

func load(fileName string) (*oauth2.Token, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	token := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(token)
	return token, err
}
