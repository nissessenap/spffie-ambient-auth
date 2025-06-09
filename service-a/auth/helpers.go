package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/NissesSenap/spffie-ambient-auth/pkg/oidc"
	"github.com/NissesSenap/spffie-ambient-auth/service-a/config"
)

// GenerateAuthURL creates the OIDC authorization URL and sets up state
func GenerateAuthURL(w http.ResponseWriter, r *http.Request, oidcClient *oidc.Client, cfg *config.Config) (string, string, error) {
	if oidcClient == nil {
		return "", "", fmt.Errorf("OIDC not initialized")
	}

	pkce, err := oidcClient.GeneratePKCE()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate PKCE: %w", err)
	}

	// Determine redirect URI based on how we're accessed
	redirectURI := fmt.Sprintf("http://localhost:%s/callback", cfg.DefaultCallbackPort)
	if host := r.Header.Get("Host"); host != "" {
		if strings.Contains(host, fmt.Sprintf("localhost:%s", cfg.DefaultCallbackPort)) {
			redirectURI = fmt.Sprintf("http://localhost:%s/callback", cfg.DefaultCallbackPort)
		} else {
			redirectURI = fmt.Sprintf("http://%s/callback", host)
		}
	}
	pkce.RedirectURI = redirectURI

	// Create state JWT for stateless operation
	tokenString, err := oidc.CreateStateJWT(pkce, cfg.OIDCSecret)
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
func ExtractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("missing or invalid Authorization header")
	}
	return authHeader, nil
}
