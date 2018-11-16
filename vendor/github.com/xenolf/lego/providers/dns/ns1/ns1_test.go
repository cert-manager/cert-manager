package ns1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest("NS1_API_KEY").
	WithDomain("NS1_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"NS1_API_KEY": "123",
			},
		},
		{
			desc: "missing api key",
			envVars: map[string]string{
				"NS1_API_KEY": "",
			},
			expected: "ns1: some credentials information are missing: NS1_API_KEY",
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
		apiKey   string
		expected string
	}{
		{
			desc:   "success",
			apiKey: "123",
		},
		{
			desc:     "missing credentials",
			expected: "ns1: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.APIKey = test.apiKey

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

func Test_getAuthZone(t *testing.T) {
	type expected struct {
		AuthZone string
		Error    string
	}

	testCases := []struct {
		desc     string
		fqdn     string
		expected expected
	}{
		{
			desc: "valid fqdn",
			fqdn: "_acme-challenge.myhost.sub.example.com.",
			expected: expected{
				AuthZone: "example.com",
			},
		},
		{
			desc: "invalid fqdn",
			fqdn: "_acme-challenge.myhost.sub.example.com",
			expected: expected{
				Error: "dns: domain must be fully qualified",
			},
		},
		{
			desc: "invalid authority",
			fqdn: "_acme-challenge.myhost.sub.domain.tld.",
			expected: expected{
				Error: "could not find the start of authority",
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			authZone, err := getAuthZone(test.fqdn)

			if len(test.expected.Error) > 0 {
				assert.EqualError(t, err, test.expected.Error)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expected.AuthZone, authZone)
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
