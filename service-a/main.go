package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/oauth2"
)

// OIDC configuration
type OIDCConfig struct {
	Provider     *oidc.Provider
	OAuth2Config oauth2.Config
	Verifier     *oidc.IDTokenVerifier
}

var oidcConfig *OIDCConfig

// PKCE state for stateless operation
type PKCEState struct {
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`
	State         string `json:"state"`
	RedirectURI   string `json:"redirect_uri"`
}

func initOIDC() error {
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "http://keycloak.keycloak.svc.cluster.local:80"
		// For development with port-forward
		if os.Getenv("DEV_MODE") == "true" {
			keycloakURL = "http://localhost:8080"
		}
	}

	clientID := os.Getenv("OIDC_CLIENT_ID")
	if clientID == "" {
		clientID = "myapp-client"
	}

	realm := os.Getenv("OIDC_REALM")
	if realm == "" {
		realm = "myapp"
	}

	issuerURL := fmt.Sprintf("%s/realms/%s", keycloakURL, realm)
	log.Printf("[oidc] Initializing OIDC with issuer: %s", issuerURL)

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oidcConfig = &OIDCConfig{
		Provider: provider,
		OAuth2Config: oauth2.Config{
			ClientID: clientID,
			Endpoint: provider.Endpoint(),
			Scopes:   []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		},
		Verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
	}

	log.Println("[oidc] OIDC configuration initialized successfully")
	return nil
}

func generatePKCE() (PKCEState, error) {
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

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if oidcConfig == nil {
		http.Error(w, "OIDC not initialized", http.StatusInternalServerError)
		return
	}

	pkce, err := generatePKCE()
	if err != nil {
		http.Error(w, "Failed to generate PKCE", http.StatusInternalServerError)
		return
	}

	// Determine redirect URI based on how we're accessed
	redirectURI := "http://localhost:8090/callback"
	if host := r.Header.Get("Host"); host != "" {
		if strings.Contains(host, "localhost:8090") {
			redirectURI = "http://localhost:8090/callback"
		} else {
			redirectURI = fmt.Sprintf("http://%s/callback", host)
		}
	}
	pkce.RedirectURI = redirectURI

	// Encode PKCE state as JWT for stateless operation
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"code_verifier":  pkce.CodeVerifier,
		"code_challenge": pkce.CodeChallenge,
		"state":          pkce.State,
		"redirect_uri":   pkce.RedirectURI,
		"exp":            time.Now().Add(10 * time.Minute).Unix(),
	})

	secret := []byte("your-secret-key") // In production, use a proper secret
	tokenString, err := token.SignedString(secret)
	if err != nil {
		http.Error(w, "Failed to create state token", http.StatusInternalServerError)
		return
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
	authURL := oidcConfig.OAuth2Config.AuthCodeURL(pkce.State,
		oauth2.SetAuthURLParam("code_challenge", pkce.CodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("redirect_uri", redirectURI),
	)

	// Return JSON response with auth URL for API clients
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"auth_url": authURL,
		"state":    pkce.State,
	})
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	if oidcConfig == nil {
		http.Error(w, "OIDC not initialized", http.StatusInternalServerError)
		return
	}

	// Get state from cookie
	cookie, err := r.Cookie("oidc_state")
	if err != nil {
		http.Error(w, "Missing state cookie", http.StatusBadRequest)
		return
	}

	// Parse state JWT
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid state token", http.StatusBadRequest)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid state claims", http.StatusBadRequest)
		return
	}

	expectedState, _ := claims["state"].(string)
	codeVerifier, _ := claims["code_verifier"].(string)
	redirectURI, _ := claims["redirect_uri"].(string)

	// Verify state parameter
	if r.URL.Query().Get("state") != expectedState {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	oidcConfig.OAuth2Config.RedirectURL = redirectURI
	oauth2Token, err := oidcConfig.OAuth2Config.Exchange(r.Context(), r.URL.Query().Get("code"),
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
		return
	}

	// Extract ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token in token response", http.StatusInternalServerError)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Return tokens
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": oauth2Token.AccessToken,
		"id_token":     rawIDToken,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(oauth2Token.Expiry).Seconds()),
	})
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	// Extract JWT token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse JWT without verification (we'll verify in service-b)
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		http.Error(w, "Invalid token format", http.StatusBadRequest)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusBadRequest)
		return
	}

	// Return user info from JWT claims
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":         claims["sub"],
		"email":       claims["email"],
		"given_name":  claims["given_name"],
		"family_name": claims["family_name"],
		"groups":      claims["groups"],
		"iss":         claims["iss"],
		"aud":         claims["aud"],
	})
}

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

	// Extract JWT token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid Authorization header. Please login first via /login", http.StatusUnauthorized)
		return
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

	// Forward the JWT token to service-b
	req.Header.Set("Authorization", authHeader)
	log.Printf("[debug] Forwarding JWT token to service-b for user authorization")

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
	resp, err := client.Get("https://service-b:8080/hello")
	if err != nil {
		http.Error(w, "Failed to call service-b: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func main() {
	ctx := context.Background()

	log.Println("[startup] Starting service-a...")
	socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socket == "" {
		socket = "unix:///run/spire/sockets/agent.sock"
	}
	log.Printf("[startup] Using SPIFFE_ENDPOINT_SOCKET=%s", socket)

	// Initialize OIDC
	if err := initOIDC(); err != nil {
		log.Printf("[warning] Failed to initialize OIDC: %v (OIDC endpoints will not work)", err)
	}

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

	// Legacy endpoints (for compatibility)
	mux.HandleFunc("/hello", helloHandler)
	mux.HandleFunc("/call-b", callServiceBHandler)

	// OIDC endpoints
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/callback", callbackHandler)
	mux.HandleFunc("/userinfo", userinfoHandler)

	// Document operation endpoints (now require JWT)
	mux.HandleFunc("/documents/view", viewDocumentHandler)
	mux.HandleFunc("/documents/edit", editDocumentHandler)
	mux.HandleFunc("/documents/delete", deleteDocumentHandler)

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

	// Start plain HTTP server for OIDC endpoints (needed for development)
	plainMux := http.NewServeMux()
	plainMux.HandleFunc("/login", loginHandler)
	plainMux.HandleFunc("/callback", callbackHandler)
	plainMux.HandleFunc("/userinfo", userinfoHandler)
	plainMux.HandleFunc("/hello", helloHandler)

	log.Println("[startup] service-a plain HTTP server listening on :8081 (for OIDC endpoints)")
	if err := http.ListenAndServe(":8081", plainMux); err != nil {
		log.Fatalf("[fatal] Plain HTTP server failed: %v", err)
	}
}
