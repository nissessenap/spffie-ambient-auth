package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	token := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
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

	// Require mTLS and verify client has a SPIFFE ID
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())

	server := &http.Server{
		Addr:      ":8080",
		Handler:   http.HandlerFunc(helloHandler),
		TLSConfig: tlsConfig,
	}

	log.Println("service-b mTLS server listening on :8080")
	log.Fatal(server.ListenAndServeTLS("", "")) // certs are provided by SPIRE
}
