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
// Automatically determines if the subject is a service (SPIFFE ID) or user (UUID)
func (c *Client) CheckPermission(ctx context.Context, resource string, permission string, subject string) (bool, error) {
	// Determine subject type based on format
	subjectType := "user"
	subjectId := subject

	if strings.HasPrefix(subject, "spiffe://") {
		subjectType = "service"
		// Convert SPIFFE ID to SpiceDB format
		converted, err := GetSVIDInSSpaceDBFormat(subject)
		if err != nil {
			return false, fmt.Errorf("failed to convert SPIFFE ID: %w", err)
		}
		subjectId = converted
	} else {
		// For user IDs, sanitize to ensure SpiceDB compatibility
		subjectId = sanitizeUserID(subject)
	}

	return c.CheckPermissionWithType(ctx, resource, permission, subjectId, subjectType)
}

// CheckPermissionWithType checks permission with explicit subject type
func (c *Client) CheckPermissionWithType(ctx context.Context, resource string, permission string, subject string, subjectType string) (bool, error) {
	resp, err := c.client.CheckPermission(ctx, &pb.CheckPermissionRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "document",
			ObjectId:   resource,
		},
		Permission: permission,
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{
				ObjectType: subjectType,
				ObjectId:   subject,
			},
		},
	})

	if err != nil {
		return false, err
	}

	return resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}

// sanitizeUserID sanitizes user IDs to be SpiceDB compatible
// Replaces hyphens with underscores to avoid regex validation issues
func sanitizeUserID(userID string) string {
	return strings.ReplaceAll(userID, "-", "_")
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
