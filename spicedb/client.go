package spicedb

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client is a wrapper for the SpiceDB client
type Client struct {
	client *authzed.Client
}

// NewClient creates a new SpiceDB client
func NewClient(ctx context.Context) (*Client, error) {
	endpoint := os.Getenv("SPICEDB_ENDPOINT")
	if endpoint == "" {
		endpoint = "dev.spicedb:50051"
	}

	presharedKey := os.Getenv("SPICEDB_PRESHARED_KEY")
	if presharedKey == "" {
		presharedKey = "averysecretpresharedkey"
	}

	log.Printf("[spicedb] Connecting to SpiceDB at %s", endpoint)

	client, err := authzed.NewClient(
		endpoint,
		grpcutil.WithInsecureBearerToken(presharedKey),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}

	return &Client{client: client}, nil
}

// CheckPermission checks if the subject has the specified permission on the resource
func (c *Client) CheckPermission(ctx context.Context, resource string, permission string, subject string) (bool, error) {
	resp, err := c.client.CheckPermission(ctx, &pb.CheckPermissionRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "document",
			ObjectId:   resource,
		},
		Permission: permission,
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{
				ObjectType: "service",
				ObjectId:   subject,
			},
		},
	})

	if err != nil {
		return false, err
	}

	return resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}

// GetServiceFromSVID extracts the service name from a SPIFFE ID
// Example: spiffe://example.org/ns/app/sa/service-a -> service-a
func GetServiceFromSVID(svidString string) string {
	// This is a simplified implementation - in production, you would want to parse the SVID more carefully
	parts := []rune(svidString)
	lastSlashIndex := -1

	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == '/' {
			lastSlashIndex = i
			break
		}
	}

	if lastSlashIndex >= 0 && lastSlashIndex < len(parts)-1 {
		return string(parts[lastSlashIndex+1:])
	}

	return ""
}

// GetSVIDInSSpaceDBFormat converts a SPIFFE ID to the format used by SpiceDB schema
// Example: spiffe://example.org/ns/app/sa/service-a ->  spiffe-example-org-ns-app-sa-service-a
func GetSVIDInSSpaceDBFormat(svidString string) (string, error) {
	if svidString == "" {
		return "", fmt.Errorf("SVID string cannot be empty")
	}

	// Verify the SPIFFE URI format
	prefix := "spiffe://"
	if !strings.HasPrefix(svidString, prefix) {
		return "", fmt.Errorf("invalid SVID format")
	}

	// For the case with no path segments (like "spiffe://example.org"), return empty as per test spec
	if !strings.Contains(svidString[len(prefix):], "/") {
		return "", fmt.Errorf("SVID string must contain at least one path segment")
	}

	// Extract domain and path parts
	withoutScheme := svidString[len(prefix):]

	// Build result with dashes instead of dots and slashes
	result := "spiffe-"
	for _, char := range withoutScheme {
		switch char {
		case '.', '/':
			result += "-"
		default:
			result += string(char)
		}
	}

	return result, nil
}
