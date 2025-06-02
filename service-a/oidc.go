package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	Provider     *oidc.Provider
	OAuth2Config *oauth2.Config
	Verifier     *oidc.IDTokenVerifier
}

type UserInfo struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	Name          string   `json:"name"`
	Groups        []string `json:"groups"`
	EmailVerified bool     `json:"email_verified"`
	PreferredName string   `json:"preferred_username"`
}

var (
	oidcConfig *OIDCConfig
	// Store PKCE verifiers temporarily (in production, use a proper session store)
	pkceVerifiers = make(map[string]string)
)

func initOIDC() error {
	providerURL := os.Getenv("OIDC_PROVIDER_URL")
	if providerURL == "" {
		providerURL = "http://localhost:9000/application/o/service-a"
	}
	log.Printf("[oidc] Using provider URL: %s", providerURL)

	clientID := os.Getenv("OIDC_CLIENT_ID")
	if clientID == "" {
		clientID = "service-a"
	}
	log.Printf("[oidc] Using client ID: %s", clientID)

	redirectURL := os.Getenv("OIDC_REDIRECT_URL")
	if redirectURL == "" {
		redirectURL = "http://localhost:8080/callback"
	}
	log.Printf("[oidc] Using redirect URL: %s", redirectURL)

	ctx := context.Background()
	log.Printf("[oidc] Attempting to create OIDC provider...")

	// Create a custom HTTP client with logging
	httpClient := &http.Client{
		Transport: &loggingTransport{
			base: http.DefaultTransport,
		},
	}
	ctx = oidc.ClientContext(ctx, httpClient)

	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		log.Printf("[oidc] Failed to create OIDC provider: %v", err)
		return fmt.Errorf("failed to create OIDC provider: %v", err)
	}
	log.Printf("[oidc] Successfully created OIDC provider")

	config := &oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirectURL,
		Endpoint:    provider.Endpoint(),
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}
	log.Printf("[oidc] Created OAuth2 config with scopes: %v", config.Scopes)

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})
	log.Printf("[oidc] Created token verifier")

	oidcConfig = &OIDCConfig{
		Provider:     provider,
		OAuth2Config: config,
		Verifier:     verifier,
	}
	log.Printf("[oidc] OIDC initialization completed successfully")

	return nil
}

// loggingTransport is a custom transport that logs HTTP requests and responses
type loggingTransport struct {
	base http.RoundTripper
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("[http] Request: %s %s", req.Method, req.URL.String())

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		log.Printf("[http] Error: %v", err)
		return nil, err
	}

	log.Printf("[http] Response: %s", resp.Status)
	return resp, nil
}

// generatePKCEVerifier generates a random PKCE verifier
func generatePKCEVerifier() (string, string, error) {
	verifier := make([]byte, 32)
	if _, err := rand.Read(verifier); err != nil {
		return "", "", err
	}
	verifierStr := base64.RawURLEncoding.EncodeToString(verifier)

	// Generate code challenge using SHA256
	hash := sha256.Sum256([]byte(verifierStr))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return verifierStr, challenge, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Generate PKCE verifier and challenge
	verifier, challenge, err := generatePKCEVerifier()
	if err != nil {
		http.Error(w, "Failed to generate PKCE verifier", http.StatusInternalServerError)
		return
	}

	// Store verifier for later use
	state := base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
	pkceVerifiers[state] = verifier

	// Create auth URL with PKCE
	authURL := oidcConfig.OAuth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get state and code from query parameters
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	// Retrieve PKCE verifier
	verifier, ok := pkceVerifiers[state]
	if !ok {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	delete(pkceVerifiers, state) // Clean up

	// Exchange code for token
	token, err := oidcConfig.OAuth2Config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token", http.StatusInternalServerError)
		return
	}

	// Verify ID token
	idToken, err := oidcConfig.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract user info
	var userInfo UserInfo
	if err := idToken.Claims(&userInfo); err != nil {
		http.Error(w, "Failed to parse user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store user info in session (in production, use a proper session store)
	// For now, we'll just return it as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": userInfo,
		"token": map[string]string{
			"access_token": token.AccessToken,
			"id_token":     rawIDToken,
		},
	})
}

func validateToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		ctx := r.Context()

		// Verify the token
		idToken, err := oidcConfig.Verifier.Verify(ctx, token)
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Extract user info
		var userInfo UserInfo
		if err := idToken.Claims(&userInfo); err != nil {
			http.Error(w, "Failed to parse user info: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Add user info to request context
		ctx = context.WithValue(ctx, "user", userInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
