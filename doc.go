// Package oauth2kit provides a simplified interface for OAuth2 authentication flows
// with built-in token management and local callback server support.
//
// The package wraps golang.org/x/oauth2 to provide additional functionality
// including automatic token persistence, retrieval, and a local HTTP server for handling
// OAuth2 callback redirects during the authorization code flow.
//
// Basic usage:
//
//	config := oauth2kit.Config{
//	    ClientID:     os.Getenv("CLIENT_ID"),
//	    ClientSecret: os.Getenv("CLIENT_SECRET"),
//	    Endpoint:     google.Endpoint,
//	    Scopes:       []string{"email", "profile"},
//	    TokenFile:    "token.json",
//	}
//	
//	manager := &oauth2kit.Manager{
//	    Config: config,
//	}
//	
//	// Get OAuth2 client with automatic token management
//	client, err := manager.NewOAuth2Client(context.Background())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	
//	// Use the client for authenticated requests
//	resp, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo")
//
// Configuration:
//
// The Config struct contains all OAuth2 settings:
//   - ClientID and ClientSecret: OAuth2 credentials
//   - Endpoint: Provider's OAuth2 endpoint (e.g., google.Endpoint)
//   - Scopes: List of permission scopes
//   - TokenFile: Path to persist tokens (default: "token.json")
//   - LocalAddr: Local server address for callback (default: ":15440")
//   - ServerPath: Callback path (default: "/callback")
//
// Token Management:
//
// The Manager handles the complete OAuth2 flow:
//   - Opens the authorization URL in the user's browser
//   - Starts a local HTTP server to receive the callback
//   - Exchanges the authorization code for an access token
//   - Persists the token to disk for reuse
//   - Automatically refreshes expired tokens
//
// Tokens are stored in JSON format at the path specified by Config.TokenFile.
// If a valid token exists, it will be reused without initiating a new authorization flow.
//
// Advanced Usage:
//
// For manual token management, use GetToken and TokenSource methods:
//
//	token, err := manager.GetToken(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	
//	tokenSource := manager.TokenSource(ctx, token)
//	client := oauth2.NewClient(ctx, tokenSource)
//
// Logging:
//
// The Manager supports custom logging through the LoggerRepository interface:
//
//	manager := &oauth2kit.Manager{
//	    Config:           config,
//	    LoggerRepository: customLogger,
//	}
//
// Thread Safety:
//
// The Manager type is safe for concurrent use after initialization.
// Multiple goroutines may call GetToken, TokenSource, and NewOAuth2Client methods simultaneously.
package oauth2kit
