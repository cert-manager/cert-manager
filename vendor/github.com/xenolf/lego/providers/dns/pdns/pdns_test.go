package pdns

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"PDNS_API_URL",
	"PDNS_API_KEY").
	WithDomain("PDNS_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"PDNS_API_KEY": "123",
				"PDNS_API_URL": "http://example.com",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"PDNS_API_KEY": "",
				"PDNS_API_URL": "",
			},
			expected: "pdns: some credentials information are missing: PDNS_API_KEY,PDNS_API_URL",
		},
		{
			desc: "missing api key",
			envVars: map[string]string{
				"PDNS_API_KEY": "",
				"PDNS_API_URL": "http://example.com",
			},
			expected: "pdns: some credentials information are missing: PDNS_API_KEY",
		},
		{
			desc: "missing API URL",
			envVars: map[string]string{
				"PDNS_API_KEY": "123",
				"PDNS_API_URL": "",
			},
			expected: "pdns: some credentials information are missing: PDNS_API_URL",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer envTest.RestoreEnv()
			envTest.ClearEnv()

			envTest.Apply(test.envVars)

			p, err := NewDNSProvider()

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

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc     string
		apiKey   string
		host     *url.URL
		expected string
	}{
		{
			desc:   "success",
			apiKey: "123",
			host: func() *url.URL {
				u, _ := url.Parse("http://example.com")
				return u
			}(),
		},
		{
			desc:     "missing credentials",
			expected: "pdns: API key missing",
		},
		{
			desc:   "missing API key",
			apiKey: "",
			host: func() *url.URL {
				u, _ := url.Parse("http://example.com")
				return u
			}(),
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
			config := NewDefaultConfig()
			config.APIKey = test.apiKey
			config.Host = test.host

			p, err := NewDNSProviderConfig(config)

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
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	provider, err := NewDNSProvider()
	require.NoError(t, err)

	err = provider.Present(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}
