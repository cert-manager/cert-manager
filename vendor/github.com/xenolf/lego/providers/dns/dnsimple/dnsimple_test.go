package dnsimple

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/platform/tester"
)

const sandboxURL = "https://api.sandbox.fake.com"

var envTest = tester.NewEnvTest(
	"DNSIMPLE_OAUTH_TOKEN",
	"DNSIMPLE_BASE_URL").
	WithDomain("DNSIMPLE_DOMAIN").
	WithLiveTestRequirements("DNSIMPLE_OAUTH_TOKEN", "DNSIMPLE_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc      string
		userAgent string
		envVars   map[string]string
		expected  string
	}{
		{
			desc:      "success",
			userAgent: "lego",
			envVars: map[string]string{
				"DNSIMPLE_OAUTH_TOKEN": "my_token",
			},
		},
		{
			desc: "success: base url",
			envVars: map[string]string{
				"DNSIMPLE_OAUTH_TOKEN": "my_token",
				"DNSIMPLE_BASE_URL":    "https://api.dnsimple.test",
			},
		},
		{
			desc: "missing oauth token",
			envVars: map[string]string{
				"DNSIMPLE_OAUTH_TOKEN": "",
			},
			expected: "dnsimple: OAuth token is missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer envTest.RestoreEnv()
			envTest.ClearEnv()

			envTest.Apply(test.envVars)

			if test.userAgent != "" {
				acme.UserAgent = test.userAgent
			}

			p, err := NewDNSProvider()

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.client)

				baseURL := os.Getenv("DNSIMPLE_BASE_URL")
				if baseURL != "" {
					assert.Equal(t, baseURL, p.client.BaseURL)
				}

				if test.userAgent != "" {
					assert.Equal(t, "lego", p.client.UserAgent)
				}

			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc        string
		accessToken string
		baseURL     string
		expected    string
	}{
		{
			desc:        "success",
			accessToken: "my_token",
			baseURL:     "",
		},
		{
			desc:        "success: base url",
			accessToken: "my_token",
			baseURL:     "https://api.dnsimple.test",
		},
		{
			desc:     "missing oauth token",
			expected: "dnsimple: OAuth token is missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.AccessToken = test.accessToken
			config.BaseURL = test.baseURL

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.client)

				if test.baseURL != "" {
					assert.Equal(t, test.baseURL, p.client.BaseURL)
				}

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

	if len(os.Getenv("DNSIMPLE_BASE_URL")) == 0 {
		os.Setenv("DNSIMPLE_BASE_URL", sandboxURL)
	}

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

	if len(os.Getenv("DNSIMPLE_BASE_URL")) == 0 {
		os.Setenv("DNSIMPLE_BASE_URL", sandboxURL)
	}

	provider, err := NewDNSProvider()
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}
