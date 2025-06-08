package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/NissesSenap/spffie-ambient-auth/pkg/oidc"
	"github.com/NissesSenap/spffie-ambient-auth/spicedb"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// ValidateSVID creates a TLS authorization function that just validates the SVID format
// The actual authorization checks will be done in the specific HTTP handlers
func ValidateSVID(ctx context.Context) tlsconfig.Authorizer {
	return func(peerID spiffeid.ID, verifiedChains [][]*x509.Certificate) error {
		// Extract service name from peer SVID - just to validate the format is correct
		subject, err := spicedb.GetSVIDInSSpaceDBFormat(peerID.String())
		if err != nil {
			return fmt.Errorf("failed to validate SVID format: %w", err)
		}

		log.Printf("[tls] Connection established with peer: %s", subject)
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

// extractBearerToken extracts the JWT token from Authorization header
func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	return strings.TrimPrefix(authHeader, "Bearer "), nil
}

// documentHandler handles document operations (view/edit/delete)
func documentHandler(oidcClient *oidc.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Log the request details to help with debugging
		log.Printf("[debug] documentHandler received request for path: %s, method: %s", r.URL.Path, r.Method)

		spiffeID := logPeerInfo(r)
		if spiffeID == "" {
			http.Error(w, "No SPIFFE ID found in request", http.StatusUnauthorized)
			return
		}

		// Extract JWT token from Authorization header
		tokenString, err := extractBearerToken(r)
		if err != nil {
			log.Printf("[error] Failed to extract bearer token: %v", err)
			http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}

		// Verify JWT token against Keycloak using OIDC client
		userInfo, err := oidcClient.ValidateToken(r.Context(), tokenString)
		if err != nil {
			log.Printf("[error] JWT verification failed: %v", err)
			http.Error(w, "Invalid JWT token", http.StatusUnauthorized)
			return
		}

		log.Printf("[jwt] Verified JWT for user: %s, groups: %v", userInfo.Subject, userInfo.Groups)

		// Extract document ID from path
		pathParts := strings.Split(r.URL.Path, "/")
		log.Printf("[debug] Path parts: %v", pathParts)

		if len(pathParts) < 3 {
			http.Error(w, "Invalid path, should be /documents/{id}", http.StatusBadRequest)
			return
		}
		documentID := pathParts[2]

		// Create SpiceDB subject from JWT username
		// Map JWT user to SpiceDB format: user:{username}
		subject := fmt.Sprintf("user:%s", userInfo.Subject)

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
			fmt.Fprintf(w, "Accessed by user: %s (%s)\n", userInfo.Subject, userInfo.Email)
		case http.MethodPut:
			// Edit operation
			fmt.Fprintf(w, "Updated document %s successfully\n", documentID)
			fmt.Fprintf(w, "Updated by user: %s (%s)\n", userInfo.Subject, userInfo.Email)
		case http.MethodDelete:
			// Delete operation
			fmt.Fprintf(w, "Deleted document %s successfully\n", documentID)
			fmt.Fprintf(w, "Deleted by user: %s (%s)\n", userInfo.Subject, userInfo.Email)
		}
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

	// Log the request details to help with debugging
	log.Printf("[debug] helloHandler received request for path: %s, method: %s", r.URL.Path, r.Method)

	fmt.Fprintf(w, "Hello from service-b!\n")
	if token != "" {
		fmt.Fprintf(w, "Received Bearer token: %s\n", token)
	} else {
		fmt.Fprintf(w, "No Bearer token received.\n")
	}
}

func main() {
	ctx := context.Background()

	// Enable development mode for testing with port-forwarding
	if os.Getenv("DEV_MODE") == "" {
		os.Setenv("DEV_MODE", "true")
		log.Printf("[config] DEV_MODE enabled for port-forward compatibility")
	}

	// Create OIDC client for JWT verification against Keycloak
	oidcClient, err := oidc.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create OIDC client: %v", err)
	}
	log.Printf("OIDC client initialized for Keycloak verification")

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

	// Require mTLS and validate client SVID
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, ValidateSVID(ctx))

	// Set up the HTTP handlers
	mux := http.NewServeMux()

	// Make sure the document handler gets precedence for /documents/ paths
	mux.HandleFunc("/documents/", documentHandler(oidcClient))
	mux.HandleFunc("/hello", helloHandler)

	// Use default port for service-b if not specified
	port := "8080"
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	server := &http.Server{
		Addr:      ":" + port,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("service-b mTLS server listening on :%s", port)
	log.Fatal(server.ListenAndServeTLS("", "")) // certs are provided by SPIRE
}
