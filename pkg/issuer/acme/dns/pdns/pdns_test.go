package pdns

import (
	"os"
	"testing"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/require"
)

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc     string
		apiKey   string
		host     string
		expected string
	}{
		{
			desc:   "success",
			apiKey: "123",
			host:   "http://example.com",
		},
		{
			desc:     "missing credentials",
			expected: "pdns: API key missing",
		},
		{
			desc:     "missing API key",
			apiKey:   "",
			host:     "http://example.com",
			expected: "pdns: API key missing",
		},
		{
			desc:     "missing host",
			apiKey:   "123",
			expected: "pdns: API URL missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			p, err := NewDNSProvider(test.host, test.apiKey, 0, 0, 0, 0, []string{"127.0.0.1:53"})

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestLivePresentAndCleanup(t *testing.T) {
	host := os.Getenv("PDNS_API_URL")
	apiKey := os.Getenv("PDNS_API_KEY")
	domain := os.Getenv("PDNS_DOMAIN")

	if host == "" || apiKey == "" || domain == "" {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProvider(host, apiKey, 0, 0, 0, 0, util.RecursiveNameservers)
	require.NoError(t, err)

	err = provider.Present(domain, "_acme-challenge."+domain+".", "123d==")
	require.NoError(t, err)

	err = provider.CleanUp(domain, "_acme-challenge."+domain+".", "123d==")
	require.NoError(t, err)
}
