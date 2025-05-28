package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/NissesSenap/spffie-ambient-auth/oidc"
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

// documentHandler handles document operations (view/edit/delete)
func documentHandler(w http.ResponseWriter, r *http.Request) {
	// Log the request details to help with debugging
	log.Printf("[debug] documentHandler received request for path: %s, method: %s", r.URL.Path, r.Method)

	// First, get user info from OIDC authentication
	userInfo, err := oidc.GetUserFromContext(r.Context())
	if err != nil {
		log.Printf("[auth] No user authentication found: %v", err)
		http.Error(w, "User authentication required", http.StatusUnauthorized)
		return
	}

	log.Printf("[auth] Processing request for user: %s (groups: %v)", userInfo.Username, userInfo.Groups)

	// Extract document ID from path
	pathParts := strings.Split(r.URL.Path, "/")
	log.Printf("[debug] Path parts: %v", pathParts)

	if len(pathParts) < 3 {
		http.Error(w, "Invalid path, should be /documents/{id}", http.StatusBadRequest)
		return
	}
	documentID := pathParts[2]

	// Use the authenticated username as the subject for SpiceDB authorization
	subject := userInfo.Username

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
	log.Printf("[authz] Checking if user %s can %s document %s", subject, operation, documentID)
	allowed, err := spicedbClient.CheckPermission(ctx, documentID, permissionToCheck, subject)
	if err != nil {
		log.Printf("[error] Failed to check permission: %v", err)
		http.Error(w, "Failed to check authorization", http.StatusInternalServerError)
		return
	}

	if !allowed {
		log.Printf("[authz] Access denied: user %s is not permitted to %s document %s", subject, operation, documentID)
		http.Error(w, fmt.Sprintf("Not authorized to %s document %s", operation, documentID), http.StatusForbidden)
		return
	}

	log.Printf("[authz] Access granted: user %s is permitted to %s document %s", subject, operation, documentID)

	// Handle different operations
	switch r.Method {
	case http.MethodGet:
		// View operation
		fmt.Fprintf(w, "Retrieved document %s\n", documentID)
		fmt.Fprintf(w, "Document content: This is a sample document content for %s\n", documentID)
		fmt.Fprintf(w, "Accessed by user: %s (%s)\n", userInfo.Username, userInfo.Email)
	case http.MethodPut:
		// Edit operation
		fmt.Fprintf(w, "Updated document %s successfully\n", documentID)
		fmt.Fprintf(w, "Updated by user: %s (%s)\n", userInfo.Username, userInfo.Email)
	case http.MethodDelete:
		// Delete operation
		fmt.Fprintf(w, "Deleted document %s successfully\n", documentID)
		fmt.Fprintf(w, "Deleted by user: %s (%s)\n", userInfo.Username, userInfo.Email)
	}
}

// helloHandler is a simple greeting endpoint
func helloHandler(w http.ResponseWriter, r *http.Request) {
	logPeerInfo(r)

	// Log the request details to help with debugging
	log.Printf("[debug] helloHandler received request for path: %s, method: %s", r.URL.Path, r.Method)

	fmt.Fprintf(w, "Hello from service-b!\n")

	// Check if we have user authentication
	userInfo, err := oidc.GetUserFromContext(r.Context())
	if err == nil && userInfo != nil {
		fmt.Fprintf(w, "Authenticated user: %s (%s)\n", userInfo.Username, userInfo.Email)
		fmt.Fprintf(w, "User groups: %v\n", userInfo.Groups)
	} else {
		fmt.Fprintf(w, "No user authentication (mTLS only)\n")
	}

	// Also check for bearer token in header (legacy)
	token := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
		if userInfo == nil {
			tokenPreview := token
			if len(token) > 20 {
				tokenPreview = token[:20] + "..."
			}
			fmt.Fprintf(w, "Received Bearer token but validation failed: %s\n", tokenPreview)
		}
	}
}

// withUserAuth wraps a handler to require OIDC user authentication
func withUserAuth(tokenValidator *oidc.TokenValidator, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract and validate user token
		token := oidc.ExtractBearerToken(r)
		if token == "" {
			http.Error(w, "Missing Authorization header with Bearer token", http.StatusUnauthorized)
			return
		}

		userInfo, err := tokenValidator.ValidateToken(r.Context(), token)
		if err != nil {
			log.Printf("[auth] Token validation failed: %v", err)
			http.Error(w, "Invalid authentication token", http.StatusUnauthorized)
			return
		}

		log.Printf("[auth] Authenticated user: %s (%s)", userInfo.Username, userInfo.Email)

		// Add user info to request context
		ctx := context.WithValue(r.Context(), "userInfo", userInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// withOptionalUserAuth wraps a handler to optionally validate user authentication
func withOptionalUserAuth(tokenValidator *oidc.TokenValidator, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := oidc.ExtractBearerToken(r)
		if token != "" {
			userInfo, err := tokenValidator.ValidateToken(r.Context(), token)
			if err != nil {
				log.Printf("[auth] Optional token validation failed: %v", err)
			} else {
				log.Printf("[auth] Authenticated user: %s (%s)", userInfo.Username, userInfo.Email)
				ctx := context.WithValue(r.Context(), "userInfo", userInfo)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
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

	// Initialize OIDC token validator with PKCE provider
	// Use the new PKCE client ID
	authentikURL := "http://authentik-server.authentik.svc.cluster.local:80/application/o/spiffe-pkce-client/" // PKCE application issuer URL
	pkceClientID := "spiffe-pkce-client"                                                                       // Use PKCE client ID

	log.Printf("Initializing OIDC validator with PKCE client ID: %s", pkceClientID)
	tokenValidator, err := oidc.NewTokenValidator(ctx, authentikURL, pkceClientID)
	if err != nil {
		log.Printf("Warning: Failed to initialize OIDC validator: %v", err)
		log.Printf("Service will only support mTLS authentication")
	} else {
		log.Printf("✅ OIDC validator initialized with SPIFFE identity")
		// Ensure cleanup on exit
		defer tokenValidator.Close()
	}

	// Require mTLS and validate client SVID
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, ValidateSVID(ctx))

	// Set up the HTTP handlers
	mux := http.NewServeMux()

	// For endpoints that need user authentication, wrap with OIDC middleware if available
	if tokenValidator != nil {
		// Document operations require user authentication + authorization
		mux.HandleFunc("/documents/", withUserAuth(tokenValidator, documentHandler))
		// Hello endpoint can work with or without user auth
		mux.HandleFunc("/hello", withOptionalUserAuth(tokenValidator, helloHandler))
	} else {
		// Fallback to mTLS-only
		mux.HandleFunc("/documents/", documentHandler)
		mux.HandleFunc("/hello", helloHandler)
	}

	server := &http.Server{
		Addr:      ":8080",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Println("service-b mTLS server listening on :8080")
	log.Fatal(server.ListenAndServeTLS("", "")) // certs are provided by SPIRE
}
