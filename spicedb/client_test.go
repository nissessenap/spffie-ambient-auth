package spicedb

import (
	"testing"
)

func TestGetSVIDInSSpaceDBFormat(t *testing.T) {
	testCases := []struct {
		name        string
		svidInput   string
		expected    string
		expectError bool
	}{
		{
			name:        "Standard SVID transformation",
			svidInput:   "spiffe://example.org/ns/app/sa/service-a",
			expected:    "spiffe-example-org-ns-app-sa-service-a",
			expectError: false,
		},
		{
			name:        "Empty string",
			svidInput:   "",
			expected:    "",
			expectError: true,
		},
		{
			name:        "No path segments",
			svidInput:   "spiffe://example.org",
			expected:    "",
			expectError: true,
		},
		{
			name:        "Invalid SPIFFE URI format - missing spiffe://",
			svidInput:   "example.org/ns/app/sa/service-a",
			expected:    "",
			expectError: true,
		},
		{
			name:        "Invalid SPIFFE URI format - wrong scheme",
			svidInput:   "http://example.org/ns/app/sa/service-a",
			expected:    "",
			expectError: true,
		},
		{
			name:        "SVID with multiple dots and slashes",
			svidInput:   "spiffe://my.example.domain.org/namespace/application/serviceaccount/my-service",
			expected:    "spiffe-my-example-domain-org-namespace-application-serviceaccount-my-service",
			expectError: false,
		},
		{
			name:        "SVID with single path segment",
			svidInput:   "spiffe://example.org/service-a",
			expected:    "spiffe-example-org-service-a",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := GetSVIDInSSpaceDBFormat(tc.svidInput)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected an error but got none")
				}
				if result != tc.expected {
					t.Errorf("Expected %q, got %q", tc.expected, result)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tc.expected {
					t.Errorf("Expected %q, got %q", tc.expected, result)
				}
			}
		})
	}
}
