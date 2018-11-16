package godaddy

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"GODADDY_API_KEY",
	"GODADDY_API_SECRET").
	WithDomain("GODADDY_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"GODADDY_API_KEY":    "123",
				"GODADDY_API_SECRET": "456",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"GODADDY_API_KEY":    "",
				"GODADDY_API_SECRET": "",
			},
			expected: "godaddy: some credentials information are missing: GODADDY_API_KEY,GODADDY_API_SECRET",
		},
		{
			desc: "missing access key",
			envVars: map[string]string{
				"GODADDY_API_KEY":    "",
				"GODADDY_API_SECRET": "456",
			},
			expected: "godaddy: some credentials information are missing: GODADDY_API_KEY",
		},
		{
			desc: "missing secret key",
			envVars: map[string]string{
				"GODADDY_API_KEY":    "123",
				"GODADDY_API_SECRET": "",
			},
			expected: "godaddy: some credentials information are missing: GODADDY_API_SECRET",
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
		desc      string
		apiKey    string
		apiSecret string
		expected  string
	}{
		{
			desc:      "success",
			apiKey:    "123",
			apiSecret: "456",
		},
		{
			desc:     "missing credentials",
			expected: "godaddy: credentials missing",
		},
		{
			desc:      "missing api key",
			apiSecret: "456",
			expected:  "godaddy: credentials missing",
		},
		{
			desc:     "missing secret key",
			apiKey:   "123",
			expected: "godaddy: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.APIKey = test.apiKey
			config.APISecret = test.apiSecret

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

func TestLivePresent(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	provider, err := NewDNSProvider()
	require.NoError(t, err)

	err = provider.Present(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}

func TestLiveCleanUp(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	provider, err := NewDNSProvider()
	require.NoError(t, err)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}
