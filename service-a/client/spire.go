package client

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type SPIREClient struct {
	source *workloadapi.X509Source
	client *http.Client
}

// NewSPIREClient creates a new SPIRE-enabled HTTP client
func NewSPIREClient(ctx context.Context) (*SPIREClient, error) {
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create X509Source: %w", err)
	}

	// Get SVID for logging
	svid, err := source.GetX509SVID()
	if err != nil {
		source.Close()
		return nil, fmt.Errorf("failed to get X509SVID: %w", err)
	}
	log.Printf("[client] Created SPIRE client with SVID: %s", svid.ID)

	// Set up mTLS client
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &SPIREClient{
		source: source,
		client: httpClient,
	}, nil
}

// Close closes the underlying X509Source
func (c *SPIREClient) Close() error {
	return c.source.Close()
}

// DoRequest performs an HTTP request with mTLS authentication
func (c *SPIREClient) DoRequest(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// DocumentOperation performs a document operation on service-b
func (c *SPIREClient) DocumentOperation(ctx context.Context, serviceURL, operation, documentID, authHeader string) (*DocumentOperationResponse, error) {
	var req *http.Request
	var err error

	url := fmt.Sprintf("%s/documents/%s", serviceURL, documentID)
	log.Printf("[client] Creating %s request to URL: %s", operation, url)

	switch operation {
	case "view":
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	case "edit":
		req, err = http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader("Updated document content"))
	case "delete":
		req, err = http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	default:
		return nil, fmt.Errorf("invalid operation: %s", operation)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Forward the JWT token to service-b
	req.Header.Set("Authorization", authHeader)
	log.Printf("[client] Forwarding JWT token to service-b for user authorization")

	// Execute the request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call service-b: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return &DocumentOperationResponse{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Body:       string(body),
		Operation:  operation,
		DocumentID: documentID,
	}, nil
}

type DocumentOperationResponse struct {
	StatusCode int
	Status     string
	Body       string
	Operation  string
	DocumentID string
}

// SimpleCall performs a simple GET request to service-b
func (c *SPIREClient) SimpleCall(url string) (*http.Response, error) {
	return c.client.Get(url)
}
