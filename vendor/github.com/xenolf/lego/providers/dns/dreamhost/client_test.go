package dreamhost

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSProvider_buildQuery(t *testing.T) {
	testCases := []struct {
		desc     string
		apiKey   string
		baseURL  string
		action   string
		domain   string
		txt      string
		expected string
	}{
		{
			desc:     "success",
			apiKey:   fakeAPIKey,
			action:   cmdAddRecord,
			domain:   "domain",
			txt:      "TXTtxtTXT",
			expected: "https://api.dreamhost.com?cmd=dns-add_record&comment=Managed%2BBy%2Blego&format=json&key=asdf1234&record=domain&type=TXT&value=TXTtxtTXT",
		},
		{
			desc:    "Invalid base URL",
			apiKey:  fakeAPIKey,
			baseURL: ":",
			action:  cmdAddRecord,
			domain:  "domain",
			txt:     "TXTtxtTXT",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			config := NewDefaultConfig()
			config.APIKey = test.apiKey
			if test.baseURL != "" {
				config.BaseURL = test.baseURL
			}

			provider, err := NewDNSProviderConfig(config)
			require.NoError(t, err)
			require.NotNil(t, provider)

			u, err := provider.buildQuery(test.action, test.domain, test.txt)

			if test.expected == "" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expected, u.String())
			}
		})
	}
}
