package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/NissesSenap/spffie-ambient-auth/pkg/oidc"
)

// GenerateAuthURL creates the OIDC authorization URL and sets up state
func GenerateAuthURL(w http.ResponseWriter, r *http.Request, oidcClient *oidc.Client) (string, string, error) {
	if oidcClient == nil {
		return "", "", fmt.Errorf("OIDC not initialized")
	}

	pkce, err := oidcClient.GeneratePKCE()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate PKCE: %w", err)
	}

	// Determine redirect URI based on how we're accessed
	redirectURI := "http://localhost:8081/callback"
	if host := r.Header.Get("Host"); host != "" {
		if strings.Contains(host, "localhost:8081") {
			redirectURI = "http://localhost:8081/callback"
		} else {
			redirectURI = fmt.Sprintf("http://%s/callback", host)
		}
	}
	pkce.RedirectURI = redirectURI

	// Create state JWT for stateless operation
	secret := []byte("your-secret-key") // In production, use a proper secret
	tokenString, err := oidc.CreateStateJWT(pkce, secret)
	if err != nil {
		return "", "", fmt.Errorf("failed to create state token: %w", err)
	}

	// Store state in cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    tokenString,
		Path:     "/",
		MaxAge:   600, // 10 minutes
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
	})

	// Build authorization URL
	authURL := oidcClient.BuildAuthURL(pkce, redirectURI)
	return authURL, pkce.State, nil
}

// ExtractBearerToken extracts the bearer token from Authorization header
func ExtractBearerToken(r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", false
	}
	return strings.TrimPrefix(authHeader, "Bearer "), true
}
