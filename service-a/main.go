package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	// Get user info from context
	userInfo, ok := r.Context().Value("user").(UserInfo)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Hello %s!\n", userInfo.Name)
	fmt.Fprintf(w, "Email: %s\n", userInfo.Email)
	fmt.Fprintf(w, "Groups: %v\n", userInfo.Groups)
}

// handleDocumentOperation executes operations on documents in service-b
func handleDocumentOperation(w http.ResponseWriter, r *http.Request, operation string) {
	// Get user info from context
	userInfo, ok := r.Context().Value("user").(UserInfo)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

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
	log.Printf("[doc-op] %s attempting to %s document %s as %s (user: %s, groups: %v)",
		r.RemoteAddr, operation, documentID, svid.ID, userInfo.Name, userInfo.Groups)

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

	// Add user info to request headers
	req.Header.Set("X-User-Name", userInfo.Name)
	req.Header.Set("X-User-Email", userInfo.Email)
	req.Header.Set("X-User-Groups", strings.Join(userInfo.Groups, ","))

	// Send request to service-b
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to send request to service-b: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy response to client
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("[error] Failed to copy response body: %v", err)
	}
}

func viewDocumentHandler(w http.ResponseWriter, r *http.Request) {
	handleDocumentOperation(w, r, "view")
}

func editDocumentHandler(w http.ResponseWriter, r *http.Request) {
	handleDocumentOperation(w, r, "edit")
}

func deleteDocumentHandler(w http.ResponseWriter, r *http.Request) {
	handleDocumentOperation(w, r, "delete")
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
		log.Fatalf("[fatal] Failed to initialize OIDC: %v", err)
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

	// Public endpoints (no auth required)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/callback", callbackHandler)

	// Protected endpoints (require valid OIDC token)
	mux.HandleFunc("/hello", validateToken(helloHandler))
	mux.HandleFunc("/documents/view", validateToken(viewDocumentHandler))
	mux.HandleFunc("/documents/edit", validateToken(editDocumentHandler))
	mux.HandleFunc("/documents/delete", validateToken(deleteDocumentHandler))

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
