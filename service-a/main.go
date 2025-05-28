package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// PKCESession stores PKCE session data
type PKCESession struct {
	CodeVerifier  string
	CodeChallenge string
	State         string
	Nonce         string
	CreatedAt     time.Time
}

// OIDCConfig holds OIDC configuration
type OIDCConfig struct {
	AuthURL     string
	TokenURL    string
	ClientID    string
	RedirectURI string
	Scope       string
}

// TokenResponse represents OAuth2/OIDC token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// Global session storage (in production, use Redis/database)
var sessions = make(map[string]*PKCESession)

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// generatePKCE generates PKCE code verifier and challenge
func generatePKCE() (verifier, challenge string, err error) {
	// Generate code verifier (43-128 characters)
	verifier, err = generateRandomString(32) // 32 bytes = 43 chars in base64url
	if err != nil {
		return "", "", err
	}

	// Generate code challenge using S256 method
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge, nil
}

// getOIDCConfig returns the OIDC configuration for Authentik
func getOIDCConfig() *OIDCConfig {
	// For demo purposes, using localhost - in production use proper service names
	baseURL := "http://localhost:9000" // Authentik server

	return &OIDCConfig{
		AuthURL:     baseURL + "/application/o/authorize/",
		TokenURL:    baseURL + "/application/o/token/",
		ClientID:    "spiffe-pkce-client",             // Updated to use the new PKCE client ID
		RedirectURI: "http://localhost:8081/callback", // Plain HTTP for demo
		Scope:       "openid profile email groups",
	}
}

// helloHandler responds with a greeting and the received Bearer token (if any)
func helloHandler(w http.ResponseWriter, r *http.Request) {
	token := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}
	fmt.Fprintf(w, "Hello from service-a!\n")
	if token != "" {
		fmt.Fprintf(w, "Received Bearer token: %s\n", token)
	} else {
		fmt.Fprintf(w, "No Bearer token received.\n")
	}
}

// handleDocumentOperation executes operations on documents in service-b
func handleDocumentOperation(w http.ResponseWriter, r *http.Request, operation string) {
	// Extract document ID from query parameter
	documentID := r.URL.Query().Get("id")
	if documentID == "" {
		documentID = "doc1" // Default document ID
	}

	ctx := r.Context()
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		http.Error(w, "Failed to create X509Source: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer source.Close()

	// Get SVID for logging
	svid, err := source.GetX509SVID()
	if err != nil {
		http.Error(w, "Failed to get X509SVID: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[doc-op] %s attempting to %s document %s as %s", r.RemoteAddr, operation, documentID, svid.ID)

	// Set up mTLS client
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	// Prepare request based on operation
	var req *http.Request
	url := fmt.Sprintf("https://service-b:8080/documents/%s", documentID)
	log.Printf("[debug] Creating request to URL: %s with method: %s", url, operation)

	switch operation {
	case "view":
		req, err = http.NewRequest(http.MethodGet, url, nil)
	case "edit":
		req, err = http.NewRequest(http.MethodPut, url, strings.NewReader("Updated document content"))
	case "delete":
		req, err = http.NewRequest(http.MethodDelete, url, nil)
	default:
		http.Error(w, "Invalid operation", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Forward Bearer token if present in original request
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		req.Header.Set("Authorization", authHeader)
		log.Printf("[debug] Forwarding Bearer token to service-b")
	}

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to call service-b: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Display response to the client
	w.WriteHeader(resp.StatusCode)
	fmt.Fprintf(w, "Operation: %s document %s\n", operation, documentID)
	fmt.Fprintf(w, "Status: %s\n", resp.Status)
	fmt.Fprintf(w, "Response: %s\n", string(body))
}

// Handler functions for each document operation
func viewDocumentHandler(w http.ResponseWriter, r *http.Request) {
	handleDocumentOperation(w, r, "view")
}

func editDocumentHandler(w http.ResponseWriter, r *http.Request) {
	handleDocumentOperation(w, r, "edit")
}

func deleteDocumentHandler(w http.ResponseWriter, r *http.Request) {
	handleDocumentOperation(w, r, "delete")
}

func callServiceBHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		http.Error(w, "Failed to create X509Source: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer source.Close()

	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	// Create request and forward Bearer token if present
	req, err := http.NewRequest(http.MethodGet, "https://service-b:8080/hello", nil)
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Forward Bearer token if present in original request
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		req.Header.Set("Authorization", authHeader)
		log.Printf("[debug] Forwarding Bearer token to service-b")
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to call service-b: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// loginFlowHandler initiates the Authorization Code Flow with PKCE
func loginFlowHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[oidc] Starting Authorization Code Flow with PKCE")

	// Generate PKCE parameters
	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		http.Error(w, "Failed to generate PKCE parameters", http.StatusInternalServerError)
		return
	}

	// Generate state and nonce for security
	state, err := generateRandomString(16)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	nonce, err := generateRandomString(16)
	if err != nil {
		http.Error(w, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Store session data
	session := &PKCESession{
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
		State:         state,
		Nonce:         nonce,
		CreatedAt:     time.Now(),
	}
	sessions[state] = session

	config := getOIDCConfig()

	// Build authorization URL
	authURL, err := url.Parse(config.AuthURL)
	if err != nil {
		http.Error(w, "Invalid auth URL", http.StatusInternalServerError)
		return
	}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", config.ClientID)
	params.Set("redirect_uri", config.RedirectURI)
	params.Set("scope", config.Scope)
	params.Set("state", state)
	params.Set("nonce", nonce)
	// PKCE parameters
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	authURL.RawQuery = params.Encode()

	log.Printf("[oidc] Redirecting to authorization URL: %s", authURL.String())
	log.Printf("[oidc] State: %s, Code Challenge: %s", state, codeChallenge)

	// Return JSON response with auth URL for API clients, or redirect for browsers
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"auth_url": authURL.String(),
			"state":    state,
			"message":  "Visit the auth_url to complete login, then return to /callback with the authorization code",
		})
	} else {
		// Redirect for browsers
		http.Redirect(w, r, authURL.String(), http.StatusFound)
	}
}

// callbackHandler handles the OAuth2/OIDC callback with authorization code
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[oidc] Handling OAuth2 callback")

	// Extract parameters from callback
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	if errorParam != "" {
		log.Printf("[oidc] OAuth2 error: %s - %s", errorParam, r.URL.Query().Get("error_description"))
		http.Error(w, fmt.Sprintf("OAuth2 error: %s", errorParam), http.StatusBadRequest)
		return
	}

	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	if state == "" {
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	// Validate state and retrieve session
	session, exists := sessions[state]
	if !exists {
		log.Printf("[oidc] Invalid or expired state: %s", state)
		http.Error(w, "Invalid or expired session", http.StatusBadRequest)
		return
	}

	// Check session expiry (10 minutes)
	if time.Since(session.CreatedAt) > 10*time.Minute {
		delete(sessions, state)
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	log.Printf("[oidc] Valid state received, exchanging code for tokens")
	log.Printf("[oidc] Code: %s, State: %s", code, state)

	// Exchange authorization code for tokens
	tokens, err := exchangeCodeForTokens(code, session.CodeVerifier)
	if err != nil {
		log.Printf("[oidc] Token exchange failed: %v", err)
		http.Error(w, fmt.Sprintf("Token exchange failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Clean up session
	delete(sessions, state)

	log.Printf("[oidc] Token exchange successful!")
	log.Printf("[oidc] Access Token: %s...", tokens.AccessToken[:min(50, len(tokens.AccessToken))])
	log.Printf("[oidc] Token Type: %s", tokens.TokenType)
	log.Printf("[oidc] Expires In: %d seconds", tokens.ExpiresIn)

	// Return tokens to client
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"message":      "Login successful!",
		"access_token": tokens.AccessToken,
		"token_type":   tokens.TokenType,
		"expires_in":   tokens.ExpiresIn,
		"id_token":     tokens.IDToken,
	}

	if tokens.RefreshToken != "" {
		response["refresh_token"] = tokens.RefreshToken
	}

	json.NewEncoder(w).Encode(response)
}

// exchangeCodeForTokens exchanges authorization code for access tokens using PKCE
func exchangeCodeForTokens(code, codeVerifier string) (*TokenResponse, error) {
	config := getOIDCConfig()

	// Prepare token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", config.RedirectURI)
	data.Set("client_id", config.ClientID)
	data.Set("code_verifier", codeVerifier) // PKCE verification

	log.Printf("[oidc] Sending token request to: %s", config.TokenURL)
	log.Printf("[oidc] Code verifier: %s", codeVerifier)

	// Create HTTP request
	req, err := http.NewRequest("POST", config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// For public clients (no client secret), we don't send authentication
	// The PKCE code_verifier provides the security

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[oidc] Token request failed with status %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse token response
	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokens, nil
}

// testTokenHandler allows testing with an access token
func testTokenHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		// Try to get from Authorization header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if token == "" {
		http.Error(w, "Missing token parameter or Authorization header", http.StatusBadRequest)
		return
	}

	// Test the token by calling service-b
	log.Printf("[test] Testing access token by calling service-b")

	ctx := r.Context()
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		http.Error(w, "Failed to create X509Source", http.StatusInternalServerError)
		return
	}
	defer source.Close()

	// Set up mTLS client
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	// Create request to service-b
	req, err := http.NewRequest(http.MethodGet, "https://service-b:8080/hello", nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Add the access token
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Request to service-b failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Forward the response
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Legacy handlers (for compatibility with existing tests)

// callServiceBWithUserHandler authenticates a user and calls service-b with their token
func callServiceBWithUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")

	if username == "" || password == "" {
		http.Error(w, "Missing username or password", http.StatusBadRequest)
		return
	}

	// Get user token using legacy password flow
	token, err := getUserToken(username, password)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	log.Printf("✅ Got OIDC token for user %s, calling service-b", username)

	// Set up mTLS client for service-b
	ctx := r.Context()
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		http.Error(w, "Failed to create X509Source", http.StatusInternalServerError)
		return
	}
	defer source.Close()

	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	// Create request to service-b with user token
	req, err := http.NewRequest(http.MethodGet, "https://service-b:8080/hello", nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Add user's OIDC token
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Request failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Return response to client
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// documentWithUserHandler handles document operations with user authentication
func documentWithUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")
	operation := r.URL.Query().Get("operation")
	documentID := r.URL.Query().Get("id")

	if username == "" || password == "" {
		http.Error(w, "Missing username or password", http.StatusBadRequest)
		return
	}

	if operation == "" {
		operation = "view" // Default operation
	}

	if documentID == "" {
		documentID = "doc1" // Default document
	}

	// Get user token using legacy password flow
	token, err := getUserToken(username, password)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	log.Printf("✅ Got OIDC token for user %s, performing %s on document %s", username, operation, documentID)

	// Set up mTLS client for service-b
	ctx := r.Context()
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		http.Error(w, "Failed to create X509Source", http.StatusInternalServerError)
		return
	}
	defer source.Close()

	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	// Prepare request based on operation
	var method string
	var url string

	switch operation {
	case "view":
		method = http.MethodGet
	case "edit":
		method = http.MethodPut
	case "delete":
		method = http.MethodDelete
	default:
		http.Error(w, "Invalid operation. Use: view, edit, or delete", http.StatusBadRequest)
		return
	}

	url = fmt.Sprintf("https://service-b:8080/documents/%s", documentID)

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Add user's OIDC token
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Request failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Return response to client
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// getUserToken gets an OIDC access token for a user from Authentik using SPIFFE mTLS
func getUserToken(username, password string) (string, error) {
	// Use HTTPS for mTLS authentication
	authentikURL := "https://authentik-server.authentik.svc.cluster.local:443"
	tokenURL := fmt.Sprintf("%s/application/o/token/", authentikURL)

	// Use the PKCE client ID for consistency
	clientID := "spiffe-pkce-client"

	// Get our SPIFFE X.509 source for client authentication
	ctx := context.Background()
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create X509Source: %w", err)
	}
	defer source.Close()

	// Get our SVID for logging and authentication
	svid, err := source.GetX509SVID()
	if err != nil {
		return "", fmt.Errorf("failed to get SVID: %w", err)
	}
	log.Printf("[oidc] Authenticating to Authentik as SPIFFE ID: %s", svid.ID)

	// Create TLS configuration with our SPIFFE certificate for mTLS
	bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return "", fmt.Errorf("failed to get bundle: %w", err)
	}

	// Create cert pool from bundle
	authorities := bundle.X509Authorities()
	certPool := x509.NewCertPool()
	for _, cert := range authorities {
		certPool.AddCert(cert)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{svid.Certificates[0].Raw},
				PrivateKey:  svid.PrivateKey,
			},
		},
		// Add any trusted CAs from the bundle
		RootCAs: certPool,
		// Allow insecure connections for demo purposes (should be secure in production)
		InsecureSkipVerify: true,
	}

	// Prepare form data - no client_secret needed for certificate-based auth
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("password", password)
	data.Set("client_id", clientID)
	data.Set("scope", "openid profile email")

	// Create HTTP request
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Create HTTP client with SPIFFE mTLS configuration
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	log.Printf("[oidc] Successfully obtained token for user %s using SPIFFE identity %s", username, svid.ID)
	return tokenResp.AccessToken, nil
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	ctx := context.Background()

	log.Println("[startup] Starting service-a...")
	socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socket == "" {
		socket = "unix:///run/spire/sockets/agent.sock"
	}
	log.Printf("[startup] Using SPIFFE_ENDPOINT_SOCKET=%s", socket)

	// Connect to the SPIRE Workload API
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		log.Fatalf("[fatal] Unable to create X509Source: %v", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		log.Fatalf("[fatal] Unable to fetch X509SVID: %v", err)
	}
	log.Printf("[startup] Got SVID: %s", svid.ID)

	// Require mTLS and verify client has a SPIFFE ID
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", helloHandler)
	mux.HandleFunc("/call-b", callServiceBHandler)
	mux.HandleFunc("/documents/view", viewDocumentHandler)
	mux.HandleFunc("/documents/edit", editDocumentHandler)
	mux.HandleFunc("/documents/delete", deleteDocumentHandler)

	// OIDC Authorization Code Flow with PKCE endpoints
	mux.HandleFunc("/login", loginFlowHandler)      // Start OAuth2 flow
	mux.HandleFunc("/callback", callbackHandler)    // Handle OAuth2 callback
	mux.HandleFunc("/test-token", testTokenHandler) // Test access tokens

	// Legacy endpoints (keeping for compatibility)
	mux.HandleFunc("/call-b-user", callServiceBWithUserHandler)
	mux.HandleFunc("/documents/user", documentWithUserHandler)
	mux.HandleFunc("/login-flow", loginFlowHandler) // Add login flow handler

	server := &http.Server{
		Addr:      ":8080",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	// Start mTLS server
	go func() {
		log.Println("[startup] service-a mTLS server listening on :8080")
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("[fatal] ListenAndServeTLS failed: %v", err)
		}
	}()

	// Start plain HTTP server for testing (no mTLS)
	log.Println("[startup] service-a plain HTTP server listening on :8081 (no mTLS, for testing only!)")
	if err := http.ListenAndServe(":8081", mux); err != nil {
		log.Fatalf("[fatal] Plain HTTP server failed: %v", err)
	}
}
