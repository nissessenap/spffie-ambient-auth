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

		// Check if the calling service can access this service as a document with view permission
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

func helloHandler(w http.ResponseWriter, r *http.Request) {
	token := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Log TLS peer identity if available
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		uris := r.TLS.PeerCertificates[0].URIs
		if len(uris) > 0 {
			log.Printf("[info] Request from SPIFFE ID: %s", uris[0])
		}
	}

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

	server := &http.Server{
		Addr:      ":8080",
		Handler:   http.HandlerFunc(helloHandler),
		TLSConfig: tlsConfig,
	}

	log.Println("service-b mTLS server listening on :8080")
	log.Fatal(server.ListenAndServeTLS("", "")) // certs are provided by SPIRE
}
