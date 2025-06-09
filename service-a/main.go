package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/NissesSenap/spffie-ambient-auth/pkg/oidc"
	"github.com/NissesSenap/spffie-ambient-auth/service-a/config"
	"github.com/NissesSenap/spffie-ambient-auth/service-a/server"
)

func initOIDC() (*oidc.Client, error) {
	// Set DEV_MODE for local development with port-forward
	os.Setenv("DEV_MODE", "true")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return oidc.NewClient(ctx)
}

func main() {
	ctx := context.Background()

	log.Println("[startup] Starting service-a...")
	
	// Load configuration
	cfg := config.New()
	log.Printf("[startup] Using SPIFFE_ENDPOINT_SOCKET=%s", cfg.SPIFFEEndpointSocket)

	// Initialize OIDC
	oidcClient, err := initOIDC()
	if err != nil {
		log.Printf("[warning] Failed to initialize OIDC: %v (OIDC endpoints will not work)", err)
		oidcClient = nil // Set to nil so handlers can check
	}

	// Start plain HTTP server for OIDC endpoints first (independent of SPIRE)
	plainServer := server.StartPlainHTTPServer(cfg, oidcClient)
	_ = plainServer // Keep reference to avoid unused variable warning

	// Try to connect to SPIRE Workload API
	source, err := server.SetupSPIREConnection(ctx)
	if err != nil {
		log.Printf("[warning] %v (mTLS server will not start)", err)
		// Keep running with just the plain HTTP server
		select {}
	}
	defer source.Close()

	// Start mTLS server (blocking)
	if err := server.StartMTLSServer(cfg, source, oidcClient); err != nil {
		log.Fatalf("[fatal] mTLS server failed: %v", err)
	}
}
