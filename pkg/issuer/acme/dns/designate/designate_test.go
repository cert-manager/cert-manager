package designate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDNSProviderCredentialsMissing(t *testing.T) {
	_, err := NewDNSProviderCredentials(
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
	)
	assert.EqualError(t, err, "could not instantiate provider client: authentication failed: You must provide a password to authenticate")
}
