package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/NissesSenap/spffie-ambient-auth/spicedb"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// AuthorizeWithSpiceDB creates a TLS authorization function that uses SpiceDB
func AuthorizeWithSpiceDB(ctx context.Context) tlsconfig.Authorizer {
	return func(peerID spiffeid.ID, verifiedChains [][]*x509.Certificate) error {
		// Create SpiceDB client
		spicedbClient, err := spicedb.NewClient(ctx)
		if err != nil {
			return fmt.Errorf("authorization service unavailable: %w", err)
		}

		// Extract service name from peer SVID
		subject, err := spicedb.GetSVIDInSSpaceDBFormat(peerID.String())
		if err != nil {
			return fmt.Errorf("failed to get service name from SVID: %w", err)
		}
		log.Printf("[authz] Checking if %s can access service-b", subject)

		// For TLS authorization at connection level, we'll just check for the basic view permission
		// More granular checks will be done at the HTTP handler level
		allowed, err := spicedbClient.CheckPermission(ctx, "service-b", "view", subject)
		if err != nil {
			return fmt.Errorf("failed to check authorization: %w", err)
		}

		if !allowed {
			return fmt.Errorf("service %s is not authorized to access service-b", subject)
		}

		log.Printf("[authz] Access granted: %s is permitted to access service-b", subject)
		return nil
	}
}

// logPeerInfo logs information about the TLS peer
func logPeerInfo(r *http.Request) string {
	// Log TLS peer identity if available
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		uris := r.TLS.PeerCertificates[0].URIs
		if len(uris) > 0 {
			spiffeID := uris[0].String()
			log.Printf("[info] Request from SPIFFE ID: %s", spiffeID)
			return spiffeID
		}
	}
	return ""
}

// documentHandler handles document operations (view/edit/delete)
func documentHandler(w http.ResponseWriter, r *http.Request) {
	spiffeID := logPeerInfo(r)
	if spiffeID == "" {
		http.Error(w, "No SPIFFE ID found in request", http.StatusUnauthorized)
		return
	}

	// Extract document ID from path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		http.Error(w, "Invalid path, should be /documents/{id}", http.StatusBadRequest)
		return
	}
	documentID := pathParts[2]

	// Get subject name in SpiceDB format
	subject, err := spicedb.GetSVIDInSSpaceDBFormat(spiffeID)
	if err != nil {
		http.Error(w, "Invalid SPIFFE ID format", http.StatusBadRequest)
		return
	}

	// Create SpiceDB client
	ctx := r.Context()
	spicedbClient, err := spicedb.NewClient(ctx)
	if err != nil {
		log.Printf("[error] Failed to create SpiceDB client: %v", err)
		http.Error(w, "Authorization service unavailable", http.StatusServiceUnavailable)
		return
	}

	// Check specific permission based on HTTP method
	var permissionToCheck string
	var operation string

	switch r.Method {
	case http.MethodGet:
		permissionToCheck = "view"
		operation = "view"
	case http.MethodPut:
		permissionToCheck = "edit"
		operation = "edit"
	case http.MethodDelete:
		permissionToCheck = "delete"
		operation = "delete"
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check permission
	log.Printf("[authz] Checking if %s can %s document %s", subject, operation, documentID)
	allowed, err := spicedbClient.CheckPermission(ctx, documentID, permissionToCheck, subject)
	if err != nil {
		log.Printf("[error] Failed to check permission: %v", err)
		http.Error(w, "Failed to check authorization", http.StatusInternalServerError)
		return
	}

	if !allowed {
		log.Printf("[authz] Access denied: %s is not permitted to %s document %s", subject, operation, documentID)
		http.Error(w, fmt.Sprintf("Not authorized to %s document %s", operation, documentID), http.StatusForbidden)
		return
	}

	log.Printf("[authz] Access granted: %s is permitted to %s document %s", subject, operation, documentID)

	// Handle different operations
	switch r.Method {
	case http.MethodGet:
		// View operation
		fmt.Fprintf(w, "Retrieved document %s\n", documentID)
		fmt.Fprintf(w, "Document content: This is a sample document content for %s\n", documentID)
	case http.MethodPut:
		// Edit operation
		fmt.Fprintf(w, "Updated document %s successfully\n", documentID)
	case http.MethodDelete:
		// Delete operation
		fmt.Fprintf(w, "Deleted document %s successfully\n", documentID)
	}
}

// helloHandler is a simple greeting endpoint
func helloHandler(w http.ResponseWriter, r *http.Request) {
	token := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}

	logPeerInfo(r)

	fmt.Fprintf(w, "Hello from service-b!\n")
	if token != "" {
		fmt.Fprintf(w, "Received Bearer token: %s\n", token)
	} else {
		fmt.Fprintf(w, "No Bearer token received.\n")
	}
}

func main() {
	ctx := context.Background()

	// Connect to the SPIRE Workload API
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		log.Fatalf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	// Get our own SVID for logging purposes
	svid, err := source.GetX509SVID()
	if err != nil {
		log.Fatalf("Unable to fetch X509SVID: %v", err)
	}
	log.Printf("Service-B running with SVID: %s", svid.ID)

	// Require mTLS and authorize clients using SpiceDB
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, AuthorizeWithSpiceDB(ctx))

	// Set up the HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", helloHandler)
	mux.HandleFunc("/documents/", documentHandler)

	server := &http.Server{
		Addr:      ":8080",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Println("service-b mTLS server listening on :8080")
	log.Fatal(server.ListenAndServeTLS("", "")) // certs are provided by SPIRE
}
