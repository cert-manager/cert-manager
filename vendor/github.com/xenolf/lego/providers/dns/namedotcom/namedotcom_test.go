package namedotcom

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"NAMECOM_USERNAME",
	"NAMECOM_API_TOKEN").
	WithDomain("NAMEDOTCOM_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"NAMECOM_USERNAME":  "A",
				"NAMECOM_API_TOKEN": "B",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"NAMECOM_USERNAME":  "",
				"NAMECOM_API_TOKEN": "",
			},
			expected: "namedotcom: some credentials information are missing: NAMECOM_USERNAME,NAMECOM_API_TOKEN",
		},
		{
			desc: "missing username",
			envVars: map[string]string{
				"NAMECOM_USERNAME":  "",
				"NAMECOM_API_TOKEN": "B",
			},
			expected: "namedotcom: some credentials information are missing: NAMECOM_USERNAME",
		},
		{
			desc: "missing api token",
			envVars: map[string]string{
				"NAMECOM_USERNAME":  "A",
				"NAMECOM_API_TOKEN": "",
			},
			expected: "namedotcom: some credentials information are missing: NAMECOM_API_TOKEN",
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
		desc     string
		apiToken string
		username string
		expected string
	}{
		{
			desc:     "success",
			apiToken: "A",
			username: "B",
		},
		{
			desc:     "missing credentials",
			expected: "namedotcom: username is required",
		},
		{
			desc:     "missing API token",
			apiToken: "",
			username: "B",
			expected: "namedotcom: API token is required",
		},
		{
			desc:     "missing username",
			apiToken: "A",
			username: "",
			expected: "namedotcom: username is required",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.Username = test.username
			config.APIToken = test.apiToken

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

	time.Sleep(1 * time.Second)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}
