# go-oauth2kit

A Go library that simplifies OAuth2 authentication flow with built-in token management and local callback server support.

## Features

- 🔐 Simplified OAuth2 authentication flow
- 💾 Automatic token persistence and retrieval
- 🖥️ Built-in local callback server for authorization code flow
- 🔄 Token refresh handling
- 🎯 Zero external dependencies beyond `golang.org/x/oauth2`

## Installation

```bash
go get github.com/micheam/go-oauth2kit
```

## Quick Start

```go
package main

import (
    "context"
    "log"
    
    "github.com/micheam/go-oauth2kit"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
)

func main() {
    manager := &oauth2kit.Manager{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        Endpoint:     google.Endpoint,
        Scopes:       []string{"email", "profile"},
        TokenFile:    "token.json",
        LocalAddr:    ":8080", // Optional: defaults to ":15440"
    }
    
    ctx := context.Background()
    client, err := manager.NewOAuth2Client(ctx) // This will block until authentication is complete
    if err != nil {
        log.Fatalf("Failed to create OAuth2 client: %v", err)
    }

    // Now, you can use the client to make authenticated requests
    resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
    if err != nil {
        log.Fatalf("Failed to get user info: %v", err)
    }
}
```

## Requirements

- Go 1.19 or higher
- `golang.org/x/oauth2`

## License

MIT License - see [LICENSE](LICENSE) file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Michito Maeda ( https://github.com/micheam )
