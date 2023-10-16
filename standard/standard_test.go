package standard_test

import (
	"strconv"
	"testing"

	"github.com/lindsaygelle/goheader/standard"
)

// TestNew tests New.
func TestNew(t *testing.T) {
	tests := []struct {
		input    string
		expected standard.Standard
	}{
		{"1544", standard.RFC1544},
		{"1864", standard.RFC1864},
		{"2616", standard.RFC2616},
		{"2965", standard.RFC2965},
		{"3229", standard.RFC3229},
		{"4021", standard.RFC4021},
		{"5789", standard.RFC5789},
		{"5988", standard.RFC5988},
		{"6265", standard.RFC6265},
		{"6266", standard.RFC6266},
		{"6454", standard.RFC6454},
		{"7089", standard.RFC7089},
		{"7234", standard.RFC7234},
		{"7239", standard.RFC7239},
		{"7240", standard.RFC7240},
		{"7469", standard.RFC7469},
		{"7480", standard.RFC7480},
		{"7540", standard.RFC7540},
		{"8942", standard.RFC8942},
		{"9110", standard.RFC9110},
		{"9111", standard.RFC9111},
		{"9113", standard.RFC9113},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			value, err := strconv.Atoi(test.input)
			if err != nil {
				t.Fatal(err)
			}
			result := standard.New(uint16(value))
			if result != test.expected {
				t.Errorf("Expected %v, but got %v", test.expected, result)
			}
		})
	}
}
