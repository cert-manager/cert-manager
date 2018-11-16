package fastdns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"AKAMAI_HOST",
	"AKAMAI_CLIENT_TOKEN",
	"AKAMAI_CLIENT_SECRET",
	"AKAMAI_ACCESS_TOKEN").
	WithDomain("AKAMAI_TEST_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"AKAMAI_HOST":          "A",
				"AKAMAI_CLIENT_TOKEN":  "B",
				"AKAMAI_CLIENT_SECRET": "C",
				"AKAMAI_ACCESS_TOKEN":  "D",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"AKAMAI_HOST":          "",
				"AKAMAI_CLIENT_TOKEN":  "",
				"AKAMAI_CLIENT_SECRET": "",
				"AKAMAI_ACCESS_TOKEN":  "",
			},
			expected: "fastdns: some credentials information are missing: AKAMAI_HOST,AKAMAI_CLIENT_TOKEN,AKAMAI_CLIENT_SECRET,AKAMAI_ACCESS_TOKEN",
		},
		{
			desc: "missing host",
			envVars: map[string]string{
				"AKAMAI_HOST":          "",
				"AKAMAI_CLIENT_TOKEN":  "B",
				"AKAMAI_CLIENT_SECRET": "C",
				"AKAMAI_ACCESS_TOKEN":  "D",
			},
			expected: "fastdns: some credentials information are missing: AKAMAI_HOST",
		},
		{
			desc: "missing client token",
			envVars: map[string]string{
				"AKAMAI_HOST":          "A",
				"AKAMAI_CLIENT_TOKEN":  "",
				"AKAMAI_CLIENT_SECRET": "C",
				"AKAMAI_ACCESS_TOKEN":  "D",
			},
			expected: "fastdns: some credentials information are missing: AKAMAI_CLIENT_TOKEN",
		},
		{
			desc: "missing client secret",
			envVars: map[string]string{
				"AKAMAI_HOST":          "A",
				"AKAMAI_CLIENT_TOKEN":  "B",
				"AKAMAI_CLIENT_SECRET": "",
				"AKAMAI_ACCESS_TOKEN":  "D",
			},
			expected: "fastdns: some credentials information are missing: AKAMAI_CLIENT_SECRET",
		},
		{
			desc: "missing access token",
			envVars: map[string]string{
				"AKAMAI_HOST":          "A",
				"AKAMAI_CLIENT_TOKEN":  "B",
				"AKAMAI_CLIENT_SECRET": "C",
				"AKAMAI_ACCESS_TOKEN":  "",
			},
			expected: "fastdns: some credentials information are missing: AKAMAI_ACCESS_TOKEN",
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
		desc         string
		host         string
		clientToken  string
		clientSecret string
		accessToken  string
		expected     string
	}{
		{
			desc:         "success",
			host:         "A",
			clientToken:  "B",
			clientSecret: "C",
			accessToken:  "D",
		},
		{
			desc:     "missing credentials",
			expected: "fastdns: credentials are missing",
		},
		{
			desc:         "missing host",
			host:         "",
			clientToken:  "B",
			clientSecret: "C",
			accessToken:  "D",
			expected:     "fastdns: credentials are missing",
		},
		{
			desc:         "missing client token",
			host:         "A",
			clientToken:  "",
			clientSecret: "C",
			accessToken:  "D",
			expected:     "fastdns: credentials are missing",
		},
		{
			desc:         "missing client secret",
			host:         "A",
			clientToken:  "B",
			clientSecret: "",
			accessToken:  "B",
			expected:     "fastdns: credentials are missing",
		},
		{
			desc:         "missing access token",
			host:         "A",
			clientToken:  "B",
			clientSecret: "C",
			accessToken:  "",
			expected:     "fastdns: credentials are missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.ClientToken = test.clientToken
			config.ClientSecret = test.clientSecret
			config.Host = test.host
			config.AccessToken = test.accessToken

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

func TestDNSProvider_findZoneAndRecordName(t *testing.T) {
	config := NewDefaultConfig()
	config.Host = "somehost"
	config.ClientToken = "someclienttoken"
	config.ClientSecret = "someclientsecret"
	config.AccessToken = "someaccesstoken"

	provider, err := NewDNSProviderConfig(config)
	require.NoError(t, err)

	type expected struct {
		zone       string
		recordName string
	}

	testCases := []struct {
		desc     string
		fqdn     string
		domain   string
		expected expected
	}{
		{
			desc:   "Extract root record name",
			fqdn:   "_acme-challenge.bar.com.",
			domain: "bar.com",
			expected: expected{
				zone:       "bar.com",
				recordName: "_acme-challenge",
			},
		},
		{
			desc:   "Extract sub record name",
			fqdn:   "_acme-challenge.foo.bar.com.",
			domain: "foo.bar.com",
			expected: expected{
				zone:       "bar.com",
				recordName: "_acme-challenge.foo",
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			zone, recordName, err := provider.findZoneAndRecordName(test.fqdn, test.domain)
			require.NoError(t, err)
			assert.Equal(t, test.expected.zone, zone)
			assert.Equal(t, test.expected.recordName, recordName)
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

	// Present Twice to handle create / update
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
