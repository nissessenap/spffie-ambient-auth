package handlers

import (
	"fmt"
	"io"
	"net/http"

	"github.com/NissesSenap/spffie-ambient-auth/service-a/auth"
	"github.com/NissesSenap/spffie-ambient-auth/service-a/client"
	"github.com/NissesSenap/spffie-ambient-auth/service-a/config"
)

type DocumentHandler struct {
	config *config.Config
}

func NewDocumentHandler(cfg *config.Config) *DocumentHandler {
	return &DocumentHandler{
		config: cfg,
	}
}

// handleDocumentOperation executes operations on documents in service-b
func (h *DocumentHandler) handleDocumentOperation(w http.ResponseWriter, r *http.Request, operation string) {
	// Extract document ID from query parameter
	documentID := r.URL.Query().Get("id")
	if documentID == "" {
		documentID = h.config.DefaultDocumentID
	}

	// Extract JWT token from Authorization header
	authHeader, err := auth.ExtractBearerToken(r)
	if err != nil {
		http.Error(w, "Missing or invalid Authorization header. Please login first via /login", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	spireClient, err := client.NewSPIREClient(ctx)
	if err != nil {
		http.Error(w, "Failed to create SPIRE client: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer spireClient.Close()

	// Perform the document operation
	response, err := spireClient.DocumentOperation(ctx, h.config.ServiceBURL, operation, documentID, authHeader)
	if err != nil {
		http.Error(w, "Failed to perform document operation: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Display response to the client
	w.WriteHeader(response.StatusCode)
	fmt.Fprintf(w, "Operation: %s document %s\n", response.Operation, response.DocumentID)
	fmt.Fprintf(w, "Status: %s\n", response.Status)
	fmt.Fprintf(w, "Response: %s\n", response.Body)
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
	spireClient, err := client.NewSPIREClient(ctx)
	if err != nil {
		http.Error(w, "Failed to create SPIRE client: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer spireClient.Close()

	resp, err := spireClient.SimpleCall("https://service-b:8080/hello")
	if err != nil {
		http.Error(w, "Failed to call service-b: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
