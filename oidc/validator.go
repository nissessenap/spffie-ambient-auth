package oidc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	clientID    string
	spireSource *workloadapi.X509Source
	issuerURL   string
	httpClient  *http.Client
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

// ValidateAccessToken validates an OAuth2 access token by parsing JWT claims directly
// This implements Task 2 requirements:
// - Accept Authorization: Bearer <access_token> header
// - Validate JWT signature using JWKS
// - Verify standard claims (exp, aud, iss, etc.)
// - Extract user information from claims
// - Handle invalid/expired tokens
func (tv *TokenValidator) ValidateAccessToken(ctx context.Context, tokenString string) (*UserInfo, error) {
	// Use the OIDC verifier to validate the JWT signature and claims
	// This will verify the signature using JWKS and check standard claims
	idToken, err := tv.verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to verify access token signature and claims: %w", err)
	}

	// Extract all claims from the token
	var claims jwt.MapClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from token: %w", err)
	}

	fmt.Printf("[oidc-debug] Access token claims: %+v\n", claims)

	// Extract user information from the JWT claims
	userInfo, err := tv.extractUserInfoFromClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to extract user info from claims: %w", err)
	}

	fmt.Printf("[oidc-debug] Extracted UserInfo from JWT: %+v\n", userInfo)

	// If user profile information is missing from JWT claims (common with access tokens),
	// fall back to calling the UserInfo endpoint
	if userInfo.Username == "" || len(userInfo.Groups) == 0 {
		fmt.Printf("[oidc-debug] User profile data missing from JWT, calling UserInfo endpoint\n")
		userInfoFromEndpoint, err := tv.getUserInfoFromToken(ctx, tokenString)
		if err != nil {
			fmt.Printf("[oidc-debug] UserInfo endpoint call failed: %v, using JWT claims only\n", err)
			// Continue with JWT-only userInfo
		} else {
			// Merge data from UserInfo endpoint with JWT claims
			fmt.Printf("[oidc-debug] Successfully got user info from endpoint, merging data\n")
			userInfo.Username = userInfoFromEndpoint.Username
			userInfo.Email = userInfoFromEndpoint.Email
			userInfo.Name = userInfoFromEndpoint.Name
			userInfo.Groups = userInfoFromEndpoint.Groups
		}
	}

	return userInfo, nil
}

// extractUserInfoFromClaims extracts user information from JWT claims
func (tv *TokenValidator) extractUserInfoFromClaims(claims jwt.MapClaims) (*UserInfo, error) {
	// Extract subject (required)
	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'sub' claim")
	}

	// Extract other user information from claims
	userInfo := &UserInfo{
		Subject: sub,
	}

	// Extract username (try multiple claim names)
	if username, ok := claims["preferred_username"].(string); ok {
		userInfo.Username = username
	} else if username, ok := claims["username"].(string); ok {
		userInfo.Username = username
	}

	// Extract email
	if email, ok := claims["email"].(string); ok {
		userInfo.Email = email
	}

	// Extract name
	if name, ok := claims["name"].(string); ok {
		userInfo.Name = name
	}

	// Extract groups (may be array of strings or space-separated string)
	if groups, ok := claims["groups"].([]interface{}); ok {
		userInfo.Groups = make([]string, len(groups))
		for i, group := range groups {
			if groupStr, ok := group.(string); ok {
				userInfo.Groups[i] = groupStr
			}
		}
	} else if groupsStr, ok := claims["groups"].(string); ok {
		// Handle space-separated groups
		userInfo.Groups = strings.Fields(groupsStr)
	}

	return userInfo, nil
}

// getUserInfoFromToken validates an access token by calling the UserInfo endpoint
func (tv *TokenValidator) getUserInfoFromToken(ctx context.Context, accessToken string) (*UserInfo, error) {
	// Build UserInfo endpoint URL - For Authentik, UserInfo is at the OAuth provider level, not app level
	// Convert issuer URL from: http://server/application/o/app-name/
	// To UserInfo URL:       http://server/application/o/userinfo/
	baseURL := strings.TrimSuffix(tv.issuerURL, "/")

	// Remove the application-specific part and replace with userinfo
	if strings.Contains(baseURL, "/application/o/") {
		// Extract base up to /application/o/
		parts := strings.Split(baseURL, "/application/o/")
		if len(parts) >= 2 {
			userInfoURL := parts[0] + "/application/o/userinfo/"
			fmt.Printf("[oidc-debug] Converted issuer URL %s to UserInfo URL: %s\n", tv.issuerURL, userInfoURL)
			baseURL = userInfoURL
		} else {
			// Fallback: just append userinfo
			baseURL = baseURL + "/userinfo/"
		}
	} else {
		// Standard OIDC: just append userinfo
		baseURL = baseURL + "/userinfo/"
	}

	// Debug logging
	fmt.Printf("[oidc-debug] Calling UserInfo endpoint: %s\n", baseURL)

	// Create request to UserInfo endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create UserInfo request: %w", err)
	}

	// Add the access token as Bearer token
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Make the request using our SPIFFE-enabled HTTP client
	resp, err := tv.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("UserInfo request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body for debugging
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read UserInfo response: %w", err)
	}

	fmt.Printf("[oidc-debug] UserInfo response status: %d\n", resp.StatusCode)
	fmt.Printf("[oidc-debug] UserInfo response body: %s\n", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("UserInfo endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse UserInfo response
	var userInfoResp struct {
		Subject           string   `json:"sub"`
		PreferredUsername string   `json:"preferred_username"`
		Username          string   `json:"username"`
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		Groups            []string `json:"groups"`
	}

	if err := json.Unmarshal(body, &userInfoResp); err != nil {
		return nil, fmt.Errorf("failed to decode UserInfo response: %w", err)
	}

	fmt.Printf("[oidc-debug] Parsed UserInfo: %+v\n", userInfoResp)

	// Use preferred_username if username is empty
	username := userInfoResp.Username
	if username == "" {
		username = userInfoResp.PreferredUsername
	}

	userInfo := &UserInfo{
		Subject:  userInfoResp.Subject,
		Username: username,
		Email:    userInfoResp.Email,
		Name:     userInfoResp.Name,
		Groups:   userInfoResp.Groups,
	}

	fmt.Printf("[oidc-debug] Final UserInfo: %+v\n", userInfo)

	return userInfo, nil
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

// SetUserInContext adds user information to the request context
func SetUserInContext(ctx context.Context, userInfo *UserInfo) context.Context {
	return context.WithValue(ctx, userInfoKey, userInfo)
}

// GetUserFromContext extracts user information from the request context
func GetUserFromContext(ctx context.Context) (*UserInfo, error) {
	userInfo, ok := ctx.Value(userInfoKey).(*UserInfo)
	if !ok {
		return nil, errors.New("user information not found in context")
	}
	return userInfo, nil
}
