package hostingde

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"HOSTINGDE_API_KEY",
	"HOSTINGDE_ZONE_NAME").
	WithDomain("HOSTINGDE_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"HOSTINGDE_API_KEY":   "123",
				"HOSTINGDE_ZONE_NAME": "456",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"HOSTINGDE_API_KEY":   "",
				"HOSTINGDE_ZONE_NAME": "",
			},
			expected: "hostingde: some credentials information are missing: HOSTINGDE_API_KEY,HOSTINGDE_ZONE_NAME",
		},
		{
			desc: "missing access key",
			envVars: map[string]string{
				"HOSTINGDE_API_KEY":   "",
				"HOSTINGDE_ZONE_NAME": "456",
			},
			expected: "hostingde: some credentials information are missing: HOSTINGDE_API_KEY",
		},
		{
			desc: "missing zone name",
			envVars: map[string]string{
				"HOSTINGDE_API_KEY":   "123",
				"HOSTINGDE_ZONE_NAME": "",
			},
			expected: "hostingde: some credentials information are missing: HOSTINGDE_ZONE_NAME",
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
				require.NotNil(t, p.recordIDs)
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
		zoneName string
		expected string
	}{
		{
			desc:     "success",
			apiKey:   "123",
			zoneName: "456",
		},
		{
			desc:     "missing credentials",
			expected: "hostingde: API key missing",
		},
		{
			desc:     "missing api key",
			zoneName: "456",
			expected: "hostingde: API key missing",
		},
		{
			desc:     "missing zone name",
			apiKey:   "123",
			expected: "hostingde: Zone Name missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.APIKey = test.apiKey
			config.ZoneName = test.zoneName

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.recordIDs)
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
