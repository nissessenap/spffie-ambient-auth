package spicedb

import (
	"testing"
)

func TestGetSVIDInSSpaceDBFormat(t *testing.T) {
	testCases := []struct {
		name      string
		svidInput string
		expected  string
	}{
		{
			name:      "Standard SVID transformation",
			svidInput: "spiffe://example.org/ns/app/sa/service-a",
			expected:  "spiffe-example-org-ns-app-sa-service-a",
		},
		{
			name:      "Empty string",
			svidInput: "",
			expected:  "",
		},
		{
			name:      "No trailing slash",
			svidInput: "spiffe://example.org",
			expected:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GetSVIDInSSpaceDBFormat(tc.svidInput)
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}
