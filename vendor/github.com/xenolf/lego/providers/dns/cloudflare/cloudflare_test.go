package cloudflare

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"CLOUDFLARE_EMAIL",
	"CLOUDFLARE_API_KEY").
	WithDomain("CLOUDFLARE_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"CLOUDFLARE_EMAIL":   "test@example.com",
				"CLOUDFLARE_API_KEY": "123",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"CLOUDFLARE_EMAIL":   "",
				"CLOUDFLARE_API_KEY": "",
			},
			expected: "cloudflare: some credentials information are missing: CLOUDFLARE_EMAIL,CLOUDFLARE_API_KEY",
		},
		{
			desc: "missing email",
			envVars: map[string]string{
				"CLOUDFLARE_EMAIL":   "",
				"CLOUDFLARE_API_KEY": "key",
			},
			expected: "cloudflare: some credentials information are missing: CLOUDFLARE_EMAIL",
		},
		{
			desc: "missing api key",
			envVars: map[string]string{
				"CLOUDFLARE_EMAIL":   "awesome@possum.com",
				"CLOUDFLARE_API_KEY": "",
			},
			expected: "cloudflare: some credentials information are missing: CLOUDFLARE_API_KEY",
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
				assert.NotNil(t, p.config)
				assert.NotNil(t, p.client)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc      string
		authEmail string
		authKey   string
		expected  string
	}{
		{
			desc:      "success",
			authEmail: "test@example.com",
			authKey:   "123",
		},
		{
			desc:     "missing credentials",
			expected: "invalid credentials: key & email must not be empty",
		},
		{
			desc:     "missing email",
			authKey:  "123",
			expected: "invalid credentials: key & email must not be empty",
		},
		{
			desc:      "missing api key",
			authEmail: "test@example.com",
			expected:  "invalid credentials: key & email must not be empty",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.AuthEmail = test.authEmail
			config.AuthKey = test.authKey

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.NotNil(t, p.config)
				assert.NotNil(t, p.client)
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
