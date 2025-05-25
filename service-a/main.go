package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/NissesSenap/spffie-ambient-auth/spicedb"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

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

// checkRoleHandler demonstrates role-based access control with SpiceDB
func checkRoleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get the requested role from query parameter
	role := r.URL.Query().Get("role")
	if role == "" {
		role = "reader" // Default role to check
	}

	// Create workload API source
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		http.Error(w, "Failed to create X509Source: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer source.Close()

	// Get our SVID to determine our service identity
	svid, err := source.GetX509SVID()
	if err != nil {
		http.Error(w, "Failed to get X509SVID: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract service name from SVID
	serviceName := spicedb.GetServiceFromSVID(svid.ID.String())
	log.Printf("[rbac] Checking if %s has role: %s", serviceName, role)

	// Connect to SpiceDB
	spicedbClient, err := spicedb.NewClient(ctx)
	if err != nil {
		log.Printf("[error] Failed to create SpiceDB client: %v", err)
		http.Error(w, "Authorization service unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	// In a real system, we would check against a resource based on the request path
	// For this demo, we'll just check against a fixed resource "api"
	allowed, err := spicedbClient.CheckPermission(ctx, "api", role, serviceName)
	if err != nil {
		log.Printf("[error] Failed to check role permission: %v", err)
		http.Error(w, "Failed to check authorization: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if allowed {
		log.Printf("[rbac] Access granted: %s has role %s for 'api'", serviceName, role)
		fmt.Fprintf(w, "Authorization successful!\n")
		fmt.Fprintf(w, "Service %s has role '%s' for resource 'api'\n", serviceName, role)
	} else {
		log.Printf("[rbac] Access denied: %s does not have role %s for 'api'", serviceName, role)
		http.Error(w, fmt.Sprintf("Not authorized: service %s does not have role '%s'", serviceName, role), http.StatusForbidden)
	}
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
	mux.HandleFunc("/check-role", checkRoleHandler)

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
