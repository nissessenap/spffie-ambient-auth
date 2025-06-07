package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/NissesSenap/spffie-ambient-auth/pkg/oidc"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var oidcClient *oidc.Client

func initOIDC() error {
	// Set DEV_MODE for local development with port-forward
	os.Setenv("DEV_MODE", "true")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := oidc.NewClient(ctx)
	if err != nil {
		return err
	}
	oidcClient = client
	return nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if oidcClient == nil {
		http.Error(w, "OIDC not initialized", http.StatusInternalServerError)
		return
	}

	pkce, err := oidcClient.GeneratePKCE()
	if err != nil {
		http.Error(w, "Failed to generate PKCE", http.StatusInternalServerError)
		return
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
	authURL := oidcClient.BuildAuthURL(pkce, redirectURI)

	// Check if request wants JSON response
	if r.Header.Get("Accept") == "application/json" {
		// Return JSON response with auth URL for API clients
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"auth_url": authURL,
			"state":    pkce.State,
		})
		return
	}

	// Return HTML response with clickable link for browser usage
	w.Header().Set("Content-Type", "text/html")
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>OIDC Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .login-container { max-width: 600px; margin: 0 auto; }
        .login-button { 
            display: inline-block; 
            background-color: #007bff; 
            color: white; 
            padding: 10px 20px; 
            text-decoration: none; 
            border-radius: 5px; 
            margin: 20px 0;
        }
        .login-button:hover { background-color: #0056b3; }
        .url-box { 
            background-color: #f8f9fa; 
            border: 1px solid #dee2e6; 
            padding: 10px; 
            border-radius: 5px; 
            word-break: break-all; 
            font-family: monospace; 
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>OIDC Login</h1>
        <p>Click the button below to start the authentication process:</p>
        <a href="%s" class="login-button">Sign In with Keycloak</a>
        <p>Or copy this URL:</p>
        <div class="url-box">%s</div>
        <p><strong>State:</strong> %s</p>
    </div>
</body>
</html>`, authURL, authURL, pkce.State)

	fmt.Fprint(w, html)
}

func loginURLHandler(w http.ResponseWriter, r *http.Request) {
	if oidcClient == nil {
		http.Error(w, "OIDC not initialized", http.StatusInternalServerError)
		return
	}

	pkce, err := oidcClient.GeneratePKCE()
	if err != nil {
		http.Error(w, "Failed to generate PKCE", http.StatusInternalServerError)
		return
	}

	// Determine redirect URI based on how we're accessed
	redirectURI := "http://localhost:8081/callback"
	pkce.RedirectURI = redirectURI

	// Create state JWT for stateless operation
	secret := []byte("your-secret-key") // In production, use a proper secret
	tokenString, err := oidc.CreateStateJWT(pkce, secret)
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
	authURL := oidcClient.BuildAuthURL(pkce, redirectURI)

	// Return just the raw URL as plain text
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, authURL)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	if oidcClient == nil {
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
	secret := []byte("your-secret-key")
	pkce, err := oidc.ParseStateJWT(cookie.Value, secret)
	if err != nil {
		http.Error(w, "Invalid state token", http.StatusBadRequest)
		return
	}

	// Verify state parameter
	if r.URL.Query().Get("state") != pkce.State {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	oauth2Token, rawIDToken, err := oidcClient.ExchangeCodeForToken(
		r.Context(),
		r.URL.Query().Get("code"),
		pkce.CodeVerifier,
		pkce.RedirectURI,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
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
	userInfo, err := oidc.ParseTokenUnsafe(tokenString)
	if err != nil {
		http.Error(w, "Invalid token format", http.StatusBadRequest)
		return
	}

	// Return user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
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

	// Start plain HTTP server for OIDC endpoints first (independent of SPIRE)
	plainMux := http.NewServeMux()
	plainMux.HandleFunc("/login", loginHandler)
	plainMux.HandleFunc("/login-url", loginURLHandler) // Raw URL endpoint
	plainMux.HandleFunc("/callback", callbackHandler)
	plainMux.HandleFunc("/userinfo", userinfoHandler)
	plainMux.HandleFunc("/hello", helloHandler)

	plainServer := &http.Server{
		Addr:    ":8081",
		Handler: plainMux,
	}

	// Start plain HTTP server
	go func() {
		log.Println("[startup] service-a plain HTTP server listening on :8081 (for OIDC endpoints)")
		if err := plainServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[error] Plain HTTP server failed: %v", err)
		}
	}()

	// Try to connect to the SPIRE Workload API (with timeout)
	log.Println("[startup] Attempting to connect to SPIRE Workload API...")

	// Create a context with timeout for SPIRE connection
	spireCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	source, err := workloadapi.NewX509Source(spireCtx)
	if err != nil {
		log.Printf("[warning] Unable to create X509Source: %v (mTLS server will not start)", err)
		// Keep running with just the plain HTTP server
		select {}
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		log.Printf("[warning] Unable to fetch X509SVID: %v (mTLS server will not start)", err)
		// Keep running with just the plain HTTP server
		select {}
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
	mux.HandleFunc("/login-url", loginURLHandler) // Raw URL endpoint
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

	// Start mTLS server (blocking)
	log.Println("[startup] service-a mTLS server listening on :8080")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("[fatal] ListenAndServeTLS failed: %v", err)
	}
}
