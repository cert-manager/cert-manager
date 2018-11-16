package cloudxns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"CLOUDXNS_API_KEY",
	"CLOUDXNS_SECRET_KEY").
	WithDomain("CLOUDXNS_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"CLOUDXNS_API_KEY":    "123",
				"CLOUDXNS_SECRET_KEY": "456",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"CLOUDXNS_API_KEY":    "",
				"CLOUDXNS_SECRET_KEY": "",
			},
			expected: "CloudXNS: some credentials information are missing: CLOUDXNS_API_KEY,CLOUDXNS_SECRET_KEY",
		},
		{
			desc: "missing API key",
			envVars: map[string]string{
				"CLOUDXNS_API_KEY":    "",
				"CLOUDXNS_SECRET_KEY": "456",
			},
			expected: "CloudXNS: some credentials information are missing: CLOUDXNS_API_KEY",
		},
		{
			desc: "missing secret key",
			envVars: map[string]string{
				"CLOUDXNS_API_KEY":    "123",
				"CLOUDXNS_SECRET_KEY": "",
			},
			expected: "CloudXNS: some credentials information are missing: CLOUDXNS_SECRET_KEY",
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
				require.NotNil(t, p.client)
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
		secretKey string
		expected  string
	}{
		{
			desc:      "success",
			apiKey:    "123",
			secretKey: "456",
		},
		{
			desc:     "missing credentials",
			expected: "CloudXNS: credentials missing: apiKey",
		},
		{
			desc:      "missing api key",
			secretKey: "456",
			expected:  "CloudXNS: credentials missing: apiKey",
		},
		{
			desc:     "missing secret key",
			apiKey:   "123",
			expected: "CloudXNS: credentials missing: secretKey",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.APIKey = test.apiKey
			config.SecretKey = test.secretKey

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.client)
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

	time.Sleep(2 * time.Second)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}
