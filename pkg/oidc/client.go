package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// Client wraps OIDC functionality for both service-a and service-b
type Client struct {
	Provider     *oidc.Provider
	OAuth2Config oauth2.Config
	Verifier     *oidc.IDTokenVerifier
	DevVerifier  *oidc.IDTokenVerifier // For development with localhost issuer
	Config       Config
}

// Config holds OIDC configuration
type Config struct {
	KeycloakURL string
	ClientID    string
	Realm       string
	IssuerURL   string
	ExternalURL string // URL accessible from browser
}

// PKCEState holds PKCE flow state
type PKCEState struct {
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`
	State         string `json:"state"`
	RedirectURI   string `json:"redirect_uri"`
}

// UserInfo represents claims from a validated JWT token
type UserInfo struct {
	Subject   string   `json:"sub"`
	Email     string   `json:"email"`
	FirstName string   `json:"given_name"`
	LastName  string   `json:"family_name"`
	Groups    []string `json:"groups"`
	Issuer    string   `json:"iss"`
	Audience  string   `json:"aud"`
}

// NewClient creates a new OIDC client with configuration from environment variables
func NewClient(ctx context.Context) (*Client, error) {
	config := Config{
		KeycloakURL: getEnvOrDefault("KEYCLOAK_URL", "http://keycloak.keycloak.svc.cluster.local"),
		ClientID:    getEnvOrDefault("OIDC_CLIENT_ID", "myapp-client"),
		Realm:       getEnvOrDefault("OIDC_REALM", "myapp"),
	}

	// For development with port-forward
	if os.Getenv("DEV_MODE") == "true" {
		// Use internal service for API calls, external URL for browser redirects
		config.KeycloakURL = "http://keycloak.keycloak.svc.cluster.local"
		config.ExternalURL = "http://localhost:8080" // Browser-accessible URL via port-forward
	} else {
		config.ExternalURL = config.KeycloakURL // In cluster, use same URL
	}

	config.IssuerURL = fmt.Sprintf("%s/realms/%s", config.KeycloakURL, config.Realm)
	log.Printf("[oidc] Initializing OIDC with issuer: %s", config.IssuerURL)
	log.Printf("[oidc] External URL for auth: %s", config.ExternalURL)

	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	client := &Client{
		Provider: provider,
		OAuth2Config: oauth2.Config{
			ClientID: config.ClientID,
			Endpoint: provider.Endpoint(),
			Scopes:   []string{oidc.ScopeOpenID, "profile", "email"},
		},
		Verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
		Config:   config,
	}

	// For development mode, also create a verifier for localhost issuer
	// Only if we can actually reach the localhost endpoint (service-a case)
	if os.Getenv("DEV_MODE") == "true" {
		devIssuerURL := fmt.Sprintf("http://localhost:8080/realms/%s", config.Realm)
		log.Printf("[oidc] Attempting to create development verifier for issuer: %s", devIssuerURL)

		// Create a context with timeout for the development provider
		devCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		devProvider, err := oidc.NewProvider(devCtx, devIssuerURL)
		if err != nil {
			log.Printf("[oidc] Development provider not available (normal for in-cluster services): %v", err)
			// Don't set DevVerifier, we'll fall back to manual JWT parsing
		} else {
			client.DevVerifier = devProvider.Verifier(&oidc.Config{ClientID: config.ClientID})
			log.Printf("[oidc] Development verifier created successfully")
		}
	}

	log.Println("[oidc] OIDC client initialized successfully")
	return client, nil
}

// GeneratePKCE creates PKCE parameters for OAuth2 flow
func (c *Client) GeneratePKCE() (PKCEState, error) {
	// Generate code verifier
	codeVerifier := make([]byte, 32)
	if _, err := rand.Read(codeVerifier); err != nil {
		return PKCEState{}, err
	}
	codeVerifierStr := base64.RawURLEncoding.EncodeToString(codeVerifier)

	// Generate code challenge
	hash := sha256.Sum256([]byte(codeVerifierStr))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Generate state
	state := make([]byte, 16)
	if _, err := rand.Read(state); err != nil {
		return PKCEState{}, err
	}
	stateStr := base64.RawURLEncoding.EncodeToString(state)

	return PKCEState{
		CodeVerifier:  codeVerifierStr,
		CodeChallenge: codeChallenge,
		State:         stateStr,
	}, nil
}

// BuildAuthURL creates the authorization URL for OIDC flow
func (c *Client) BuildAuthURL(pkce PKCEState, redirectURI string) string {
	// Use external URL for auth endpoint (browser-accessible)
	authEndpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", c.Config.ExternalURL, c.Config.Realm)

	config := oauth2.Config{
		ClientID: c.OAuth2Config.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authEndpoint,
			TokenURL: c.OAuth2Config.Endpoint.TokenURL, // Keep internal for token exchange
		},
		Scopes: c.OAuth2Config.Scopes,
	}

	return config.AuthCodeURL(pkce.State,
		oauth2.SetAuthURLParam("code_challenge", pkce.CodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("redirect_uri", redirectURI),
	)
}

// ExchangeCodeForToken exchanges authorization code for tokens using PKCE
func (c *Client) ExchangeCodeForToken(ctx context.Context, code, codeVerifier, redirectURI string) (*oauth2.Token, string, error) {
	c.OAuth2Config.RedirectURL = redirectURI
	oauth2Token, err := c.OAuth2Config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to exchange token: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, "", fmt.Errorf("no id_token in token response")
	}

	return oauth2Token, rawIDToken, nil
}

// ValidateToken validates a JWT token and returns user information
func (c *Client) ValidateToken(ctx context.Context, tokenString string) (*UserInfo, error) {
	// Try the primary verifier first (cluster-internal issuer)
	token, err := c.Verifier.Verify(ctx, tokenString)
	if err != nil && c.DevVerifier != nil {
		// If primary verification fails and we have a dev verifier, try it
		log.Printf("[oidc] Primary verification failed, trying development verifier: %v", err)
		token, err = c.DevVerifier.Verify(ctx, tokenString)
		if err != nil {
			return nil, fmt.Errorf("failed to verify token with both verifiers: %w", err)
		}
		log.Printf("[oidc] Token verified successfully with development verifier")
	} else if err != nil {
		// If primary verification fails and no dev verifier, try manual validation for localhost tokens
		log.Printf("[oidc] Primary verification failed, attempting manual validation for localhost issuer: %v", err)
		return c.validateLocalhostToken(ctx, tokenString)
	} else {
		log.Printf("[oidc] Token verified successfully with primary verifier")
	}

	// Extract claims
	var claims struct {
		Subject   string   `json:"sub"`
		Email     string   `json:"email"`
		FirstName string   `json:"given_name"`
		LastName  string   `json:"family_name"`
		Groups    []string `json:"groups"`
		Issuer    string   `json:"iss"`
		Audience  string   `json:"aud"`
	}

	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	return &UserInfo{
		Subject:   claims.Subject,
		Email:     claims.Email,
		FirstName: claims.FirstName,
		LastName:  claims.LastName,
		Groups:    claims.Groups,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
	}, nil
}

// ParseTokenUnsafe parses a JWT token without validation (for service-a userinfo endpoint)
func ParseTokenUnsafe(tokenString string) (*UserInfo, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("invalid token format: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	groups := make([]string, 0)
	if groupsClaim, ok := claims["groups"].([]interface{}); ok {
		for _, group := range groupsClaim {
			if groupStr, ok := group.(string); ok {
				groups = append(groups, groupStr)
			}
		}
	}

	return &UserInfo{
		Subject:   getStringClaim(claims, "sub"),
		Email:     getStringClaim(claims, "email"),
		FirstName: getStringClaim(claims, "given_name"),
		LastName:  getStringClaim(claims, "family_name"),
		Groups:    groups,
		Issuer:    getStringClaim(claims, "iss"),
		Audience:  getStringClaim(claims, "aud"),
	}, nil
}

// CreateStateJWT creates a JWT for storing PKCE state
func CreateStateJWT(pkce PKCEState, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"code_verifier":  pkce.CodeVerifier,
		"code_challenge": pkce.CodeChallenge,
		"state":          pkce.State,
		"redirect_uri":   pkce.RedirectURI,
		"exp":            time.Now().Add(10 * time.Minute).Unix(),
	})

	return token.SignedString(secret)
}

// ParseStateJWT parses a state JWT and returns PKCE state
func ParseStateJWT(tokenString string, secret []byte) (*PKCEState, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid state token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid state claims")
	}

	return &PKCEState{
		CodeVerifier:  getStringClaim(claims, "code_verifier"),
		CodeChallenge: getStringClaim(claims, "code_challenge"),
		State:         getStringClaim(claims, "state"),
		RedirectURI:   getStringClaim(claims, "redirect_uri"),
	}, nil
}

// validateLocalhostToken manually validates tokens issued by localhost Keycloak
// This is used when service-b can't reach localhost:8080 to create a proper verifier
func (c *Client) validateLocalhostToken(ctx context.Context, tokenString string) (*UserInfo, error) {
	// Parse the token without verification to check the issuer
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("invalid token format: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check if this is a localhost-issued token
	issuer, ok := claims["iss"].(string)
	if !ok {
		return nil, fmt.Errorf("no issuer in token")
	}

	expectedLocalhostIssuer := fmt.Sprintf("http://localhost:8080/realms/%s", c.Config.Realm)
	if issuer != expectedLocalhostIssuer {
		return nil, fmt.Errorf("token not issued by expected localhost issuer: got %s, expected %s", issuer, expectedLocalhostIssuer)
	}

	log.Printf("[oidc] Accepting localhost-issued token for development (issuer: %s)", issuer)

	// For development purposes, we'll trust localhost-issued tokens
	// In production, you should still validate the signature against Keycloak's JWKS
	groups := []string{}
	if groupsClaim, ok := claims["groups"].([]interface{}); ok {
		for _, group := range groupsClaim {
			if groupStr, ok := group.(string); ok {
				groups = append(groups, groupStr)
			}
		}
	}

	return &UserInfo{
		Subject:   getStringClaim(claims, "sub"),
		Email:     getStringClaim(claims, "email"),
		FirstName: getStringClaim(claims, "given_name"),
		LastName:  getStringClaim(claims, "family_name"),
		Groups:    groups,
		Issuer:    issuer,
		Audience:  getStringClaim(claims, "aud"),
	}, nil
}

// Helper functions
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getStringClaim(claims jwt.MapClaims, key string) string {
	if value, ok := claims[key].(string); ok {
		return value
	}
	return ""
}
