package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"golang.org/x/oauth2/google"

	"github.com/micheam/go-oauth2kit"
)

func main() {
	config := oauth2kit.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Endpoint:     google.Endpoint,
		Scopes:       []string{"email", "profile"},
		TokenFile:    "token.json",
	}

	manager := &oauth2kit.Manager{
		Config: config,
	}

	// Get OAuth2 client with automatic token management
	// NewOAuth2Client automatically validates, refreshes, and persists tokens
	// If the token is expired, it will be refreshed and saved transparently
	client, err := manager.NewOAuth2Client(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// Use the client for authenticated requests
	// No need to manually check or refresh tokens
	resp, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	var userInfo map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Fatal(err)
	}

	// Print user info as JSON
	userInfoJSON, err := json.MarshalIndent(userInfo, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(userInfoJSON))
}
