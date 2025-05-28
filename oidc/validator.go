package oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// UserInfo represents user information extracted from the JWT token
type UserInfo struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Groups   []string `json:"groups"`
	Subject  string   `json:"sub"`
}

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const userInfoKey contextKey = "userInfo"

// TokenValidator handles OIDC token validation using SPIFFE identity
type TokenValidator struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	clientID     string
	spireSource  *workloadapi.X509Source
	issuerURL    string
	httpClient   *http.Client
}

// NewTokenValidator creates a new OIDC token validator using SPIFFE identity
func NewTokenValidator(ctx context.Context, issuerURL, clientID string) (*TokenValidator, error) {
	// Create SPIRE X509Source for mTLS authentication to Authentik
	spireSource, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPIRE X509Source: %w", err)
	}

	// Create custom HTTP client that uses SPIFFE identity for mTLS
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Use SPIFFE certificates for client authentication
				GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					svid, err := spireSource.GetX509SVID()
					if err != nil {
						return nil, fmt.Errorf("failed to get SVID: %w", err)
					}

					return &tls.Certificate{
						Certificate: [][]byte{svid.Certificates[0].Raw},
						PrivateKey:  svid.PrivateKey,
					}, nil
				},
				// For development - in production, verify Authentik's certificate
				InsecureSkipVerify: true,
			},
		},
	}

	// Create OIDC provider with custom HTTP client
	ctx = oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create verifier - no client secret needed, we use SPIFFE identity
	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
		// Skip client_secret verification since we're using SPIFFE mTLS
		SkipClientIDCheck: false,
	})

	return &TokenValidator{
		provider:    provider,
		verifier:    verifier,
		clientID:    clientID,
		spireSource: spireSource,
		issuerURL:   issuerURL,
		httpClient:  httpClient,
	}, nil
}

// ValidateAccessToken validates a JWT access token using JWKS
// This implements Task 2 requirements:
// - Accept Authorization: Bearer <access_token> header
// - Validate JWT without client secret
// - Use JWKS to verify token signature (handled by OIDC library)
// - Verify standard claims (exp, aud, iss, etc.)
// - Cache JWKS for performance (handled by OIDC library)
// - Handle invalid/expired tokens
func (tv *TokenValidator) ValidateAccessToken(ctx context.Context, tokenString string) (*UserInfo, error) {
	// Use the OIDC provider's verification which handles JWKS automatically
	// This provides proper JWT signature verification with cached JWKS
	idToken, err := tv.verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to verify access token: %w", err)
	}

	// Extract claims from the verified token
	var claims struct {
		Subject           string   `json:"sub"`
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		Groups            []string `json:"groups"`
		Audience          []string `json:"aud"`
		Issuer            string   `json:"iss"`
		ExpiresAt         int64    `json:"exp"`
		IssuedAt          int64    `json:"iat"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Verify standard claims
	now := time.Now().Unix()
	
	// Check expiration
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, fmt.Errorf("token has expired")
	}

	// Check issuer
	if claims.Issuer != "" && claims.Issuer != tv.issuerURL {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", tv.issuerURL, claims.Issuer)
	}

	// Check audience (should contain our client ID or SPIFFE identifier)
	if len(claims.Audience) > 0 {
		validAudience := false
		for _, aud := range claims.Audience {
			if aud == tv.clientID || strings.Contains(aud, "spiffe") {
				validAudience = true
				break
			}
		}
		if !validAudience {
			return nil, fmt.Errorf("invalid audience: token not intended for this client")
		}
	}

	// Parse additional claims from raw token if needed
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

	accessTokenUserInfo := &UserInfo{
		Subject:  claims.Subject,
		Username: claims.PreferredUsername,
		Email:    claims.Email,
		Name:     claims.Name,
		Groups:   allGroups,
	}

	return accessTokenUserInfo, nil
}

// ValidateToken validates a JWT token and returns user information
// This is the original method for ID token validation
func (tv *TokenValidator) ValidateToken(ctx context.Context, tokenString string) (*UserInfo, error) {
	// For backward compatibility, try access token validation first
	userInfo, err := tv.ValidateAccessToken(ctx, tokenString)
	if err == nil {
		return userInfo, nil
	}

	// Fall back to ID token validation
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
	token, _, parseErr := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	var additionalGroups []string
	if parseErr == nil && token != nil {
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

	finalUserInfo := &UserInfo{
		Subject:  claims.Subject,
		Username: claims.PreferredUsername,
		Email:    claims.Email,
		Name:     claims.Name,
		Groups:   allGroups,
	}

	return finalUserInfo, nil
}

// Close cleans up the SPIRE source
func (tv *TokenValidator) Close() {
	if tv.spireSource != nil {
		tv.spireSource.Close()
	}
}

// GetSPIFFEIdentity returns the current SPIFFE identity of this service
func (tv *TokenValidator) GetSPIFFEIdentity() (string, error) {
	if tv.spireSource == nil {
		return "", errors.New("SPIRE source not initialized")
	}

	svid, err := tv.spireSource.GetX509SVID()
	if err != nil {
		return "", fmt.Errorf("failed to get SVID: %w", err)
	}

	return svid.ID.String(), nil
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
		ctx := context.WithValue(r.Context(), userInfoKey, userInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetUserFromContext extracts user information from the request context
func GetUserFromContext(ctx context.Context) (*UserInfo, error) {
	userInfo, ok := ctx.Value(userInfoKey).(*UserInfo)
	if !ok {
		return nil, errors.New("user information not found in context")
	}
	return userInfo, nil
}
