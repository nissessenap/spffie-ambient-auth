package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

// UserInfo represents user information extracted from the JWT token
type UserInfo struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Groups   []string `json:"groups"`
	Subject  string   `json:"sub"`
}

// TokenValidator handles OIDC token validation
type TokenValidator struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	clientID string
}

// NewTokenValidator creates a new OIDC token validator
func NewTokenValidator(ctx context.Context, issuerURL, clientID string) (*TokenValidator, error) {
	// Create OIDC provider
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	return &TokenValidator{
		provider: provider,
		verifier: verifier,
		clientID: clientID,
	}, nil
}

// ValidateToken validates a JWT token and returns user information
func (tv *TokenValidator) ValidateToken(ctx context.Context, tokenString string) (*UserInfo, error) {
	// Verify the ID token
	idToken, err := tv.verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	// Extract standard claims
	var claims struct {
		Subject           string   `json:"sub"`
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		Groups            []string `json:"groups"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Parse the token to get additional claims that might not be in standard format
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})

	var additionalGroups []string
	if err == nil && token != nil {
		if mapClaims, ok := token.Claims.(jwt.MapClaims); ok {
			// Try different group claim locations that Authentik might use
			if groups, ok := mapClaims["groups"].([]interface{}); ok {
				for _, group := range groups {
					if groupStr, ok := group.(string); ok {
						additionalGroups = append(additionalGroups, groupStr)
					}
				}
			}
		}
	}

	// Merge groups from different sources
	allGroups := claims.Groups
	for _, group := range additionalGroups {
		found := false
		for _, existing := range allGroups {
			if existing == group {
				found = true
				break
			}
		}
		if !found {
			allGroups = append(allGroups, group)
		}
	}

	userInfo := &UserInfo{
		Subject:  claims.Subject,
		Username: claims.PreferredUsername,
		Email:    claims.Email,
		Name:     claims.Name,
		Groups:   allGroups,
	}

	return userInfo, nil
}

// ExtractBearerToken extracts a bearer token from the Authorization header
func ExtractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

// AuthenticateRequest is a middleware function that validates OIDC tokens
func (tv *TokenValidator) AuthenticateRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := ExtractBearerToken(r)
		if token == "" {
			http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}

		userInfo, err := tv.ValidateToken(r.Context(), token)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		// Add user info to request context
		ctx := context.WithValue(r.Context(), "userInfo", userInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetUserFromContext extracts user information from the request context
func GetUserFromContext(ctx context.Context) (*UserInfo, error) {
	userInfo, ok := ctx.Value("userInfo").(*UserInfo)
	if !ok {
		return nil, errors.New("user information not found in context")
	}
	return userInfo, nil
}
