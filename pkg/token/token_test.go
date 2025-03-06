package token

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetExtraClaims(t *testing.T) {
	testCases := []struct {
		name   string
		env    string
		expect map[string]string
	}{
		{
			name:   "empty",
			env:    "",
			expect: map[string]string{},
		},
		{
			name: "single",
			env:  "claim1=value1",
			expect: map[string]string{
				"claim1": "value1",
			},
		},
		{
			name: "multiple with special characters",
			env:  "claim1=value1;claim2={value2};claim3=value-3",
			expect: map[string]string{
				"claim1": "value1",
				"claim2": "{value2}",
				"claim3": "value-3",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("EXTRA_CLAIMS", tc.env)
			defer os.Unsetenv("EXTRA_CLAIMS")

			claims := getExtraClaims()
			assert.Equal(t, tc.expect, claims)
		})
	}
}
