package glesys

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"GLESYS_API_USER",
	"GLESYS_API_KEY").
	WithDomain("GLESYS_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"GLESYS_API_USER": "A",
				"GLESYS_API_KEY":  "B",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"GLESYS_API_USER": "",
				"GLESYS_API_KEY":  "",
			},
			expected: "glesys: some credentials information are missing: GLESYS_API_USER,GLESYS_API_KEY",
		},
		{
			desc: "missing api user",
			envVars: map[string]string{
				"GLESYS_API_USER": "",
				"GLESYS_API_KEY":  "B",
			},
			expected: "glesys: some credentials information are missing: GLESYS_API_USER",
		},
		{
			desc: "missing api key",
			envVars: map[string]string{
				"GLESYS_API_USER": "A",
				"GLESYS_API_KEY":  "",
			},
			expected: "glesys: some credentials information are missing: GLESYS_API_KEY",
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
				require.NotNil(t, p.activeRecords)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc     string
		apiUser  string
		apiKey   string
		expected string
	}{
		{
			desc:    "success",
			apiUser: "A",
			apiKey:  "B",
		},
		{
			desc:     "missing credentials",
			expected: "glesys: incomplete credentials provided",
		},
		{
			desc:     "missing api user",
			apiUser:  "",
			apiKey:   "B",
			expected: "glesys: incomplete credentials provided",
		},
		{
			desc:     "missing api key",
			apiUser:  "A",
			apiKey:   "",
			expected: "glesys: incomplete credentials provided",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.APIKey = test.apiKey
			config.APIUser = test.apiUser

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.activeRecords)
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
