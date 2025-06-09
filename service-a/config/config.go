package config

import "os"

type Config struct {
	// Server configuration
	PlainHTTPPort string
	MTLSPort      string

	// SPIRE configuration
	SPIFFEEndpointSocket string

	// OIDC configuration
	OIDCSecret          []byte
	DefaultCallbackPort string
	DevMode             bool

	// Service B configuration
	ServiceBURL string

	// Default document ID
	DefaultDocumentID string
}

func New() *Config {
	return &Config{
		PlainHTTPPort:        getEnv("PLAIN_HTTP_PORT", "8081"),
		MTLSPort:             getEnv("MTLS_PORT", "8080"),
		SPIFFEEndpointSocket: getEnv("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/sockets/agent.sock"),
		OIDCSecret:           []byte(getEnv("OIDC_SECRET", "your-secret-key")), // TODO: Use proper secret in production
		DefaultCallbackPort:  getEnv("DEFAULT_CALLBACK_PORT", "8081"),
		DevMode:              getEnv("DEV_MODE", "true") == "true",
		ServiceBURL:          getEnv("SERVICE_B_URL", "https://service-b:8080"),
		DefaultDocumentID:    getEnv("DEFAULT_DOCUMENT_ID", "doc1"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
