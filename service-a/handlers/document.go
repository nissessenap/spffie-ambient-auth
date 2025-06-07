package handlers

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type DocumentHandler struct{}

func NewDocumentHandler() *DocumentHandler {
	return &DocumentHandler{}
}

// handleDocumentOperation executes operations on documents in service-b
func (h *DocumentHandler) handleDocumentOperation(w http.ResponseWriter, r *http.Request, operation string) {
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

func (h *DocumentHandler) ViewDocumentHandler(w http.ResponseWriter, r *http.Request) {
	h.handleDocumentOperation(w, r, "view")
}

func (h *DocumentHandler) EditDocumentHandler(w http.ResponseWriter, r *http.Request) {
	h.handleDocumentOperation(w, r, "edit")
}

func (h *DocumentHandler) DeleteDocumentHandler(w http.ResponseWriter, r *http.Request) {
	h.handleDocumentOperation(w, r, "delete")
}

func CallServiceBHandler(w http.ResponseWriter, r *http.Request) {
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
