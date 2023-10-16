package status_test

import (
	"testing"

	"github.com/lindsaygelle/goheader/status"
)

// TestNew tests New.
func TestNew(t *testing.T) {
	tests := []struct {
		input    string
		expected status.Status
	}{
		{"Experimental", status.Experimental},
		{"Obsolete", status.Obsolete},
		{"Permanent", status.Permanent},
		{"Permanent:standard", status.PermanentStandard},
		{"Proposed", status.Proposed},
		{"Provisional", status.Provisional},
		{"Unknown", status.Unknown},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := status.New(test.input)
			if result != test.expected {
				t.Errorf("Expected %v, but got %v", test.expected, result)
			}
		})
	}
}
