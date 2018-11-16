package duckdns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest("DUCKDNS_TOKEN").
	WithDomain("DUCKDNS_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"DUCKDNS_TOKEN": "123",
			},
		},
		{
			desc: "missing api key",
			envVars: map[string]string{
				"DUCKDNS_TOKEN": "",
			},
			expected: "duckdns: some credentials information are missing: DUCKDNS_TOKEN",
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
		token    string
		expected string
	}{
		{
			desc:  "success",
			token: "123",
		},
		{
			desc:     "missing credentials",
			expected: "duckdns: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.Token = test.token

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

func Test_getMainDomain(t *testing.T) {
	testCases := []struct {
		desc     string
		domain   string
		expected string
	}{
		{
			desc:     "empty",
			domain:   "",
			expected: "",
		},
		{
			desc:     "missing sub domain",
			domain:   "duckdns.org",
			expected: "",
		},
		{
			desc:     "explicit domain: sub domain",
			domain:   "sub.duckdns.org",
			expected: "sub.duckdns.org",
		},
		{
			desc:     "explicit domain: subsub domain",
			domain:   "my.sub.duckdns.org",
			expected: "sub.duckdns.org",
		},
		{
			desc:     "explicit domain: subsubsub domain",
			domain:   "my.sub.sub.duckdns.org",
			expected: "sub.duckdns.org",
		},
		{
			desc:     "only subname: sub domain",
			domain:   "sub",
			expected: "sub",
		},
		{
			desc:     "only subname: subsub domain",
			domain:   "my.sub",
			expected: "sub",
		},
		{
			desc:     "only subname: subsubsub domain",
			domain:   "my.sub.sub",
			expected: "sub",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			wDomain := getMainDomain(test.domain)
			assert.Equal(t, test.expected, wDomain)
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
