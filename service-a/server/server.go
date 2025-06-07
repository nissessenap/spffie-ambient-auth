package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/NissesSenap/spffie-ambient-auth/pkg/oidc"
	"github.com/NissesSenap/spffie-ambient-auth/service-a/handlers"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SetupRoutes configures all HTTP routes for the given mux
func SetupRoutes(mux *http.ServeMux, oidcHandler *handlers.OIDCHandler, docHandler *handlers.DocumentHandler) {
	// Legacy endpoints (for compatibility)
	mux.HandleFunc("/hello", handlers.HelloHandler)
	mux.HandleFunc("/call-b", handlers.CallServiceBHandler)

	// OIDC endpoints
	mux.HandleFunc("/login", oidcHandler.LoginHandler)
	mux.HandleFunc("/login-url", oidcHandler.LoginURLHandler)
	mux.HandleFunc("/callback", oidcHandler.CallbackHandler)
	mux.HandleFunc("/userinfo", oidcHandler.UserinfoHandler)

	// Document operation endpoints (require JWT)
	mux.HandleFunc("/documents/view", docHandler.ViewDocumentHandler)
	mux.HandleFunc("/documents/edit", docHandler.EditDocumentHandler)
	mux.HandleFunc("/documents/delete", docHandler.DeleteDocumentHandler)
}

// StartPlainHTTPServer starts the HTTP server for OIDC endpoints
func StartPlainHTTPServer(oidcClient *oidc.Client) *http.Server {
	oidcHandler := handlers.NewOIDCHandler(oidcClient)
	docHandler := handlers.NewDocumentHandler()

	plainMux := http.NewServeMux()
	SetupRoutes(plainMux, oidcHandler, docHandler)

	plainServer := &http.Server{
		Addr:    ":8081",
		Handler: plainMux,
	}

	go func() {
		log.Println("[startup] service-a plain HTTP server listening on :8081 (for OIDC endpoints)")
		if err := plainServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[error] Plain HTTP server failed: %v", err)
		}
	}()

	return plainServer
}

// SetupSPIREConnection attempts to connect to SPIRE and returns the X509Source
func SetupSPIREConnection(ctx context.Context) (*workloadapi.X509Source, error) {
	log.Println("[startup] Attempting to connect to SPIRE Workload API...")

	// Create a context with timeout for SPIRE connection
	spireCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	source, err := workloadapi.NewX509Source(spireCtx)
	if err != nil {
		return nil, fmt.Errorf("unable to create X509Source: %w", err)
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		source.Close()
		return nil, fmt.Errorf("unable to fetch X509SVID: %w", err)
	}
	log.Printf("[startup] Got SVID: %s", svid.ID)

	return source, nil
}

// StartMTLSServer starts the mTLS server with SPIRE integration
func StartMTLSServer(source *workloadapi.X509Source, oidcClient *oidc.Client) error {
	// Require mTLS and verify client has a SPIFFE ID
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())

	oidcHandler := handlers.NewOIDCHandler(oidcClient)
	docHandler := handlers.NewDocumentHandler()

	mux := http.NewServeMux()
	SetupRoutes(mux, oidcHandler, docHandler)

	server := &http.Server{
		Addr:      ":8080",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	// Start mTLS server (blocking)
	log.Println("[startup] service-a mTLS server listening on :8080")
	return server.ListenAndServeTLS("", "")
}
