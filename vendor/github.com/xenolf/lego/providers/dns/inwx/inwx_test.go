package inwx

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"INWX_USERNAME",
	"INWX_PASSWORD",
	"INWX_SANDBOX",
	"INWX_TTL").
	WithDomain("INWX_DOMAIN").
	WithLiveTestRequirements("INWX_USERNAME", "INWX_PASSWORD", "INWX_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"INWX_USERNAME": "123",
				"INWX_PASSWORD": "456",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"INWX_USERNAME": "",
				"INWX_PASSWORD": "",
			},
			expected: "inwx: some credentials information are missing: INWX_USERNAME,INWX_PASSWORD",
		},
		{
			desc: "missing username",
			envVars: map[string]string{
				"INWX_USERNAME": "",
				"INWX_PASSWORD": "456",
			},
			expected: "inwx: some credentials information are missing: INWX_USERNAME",
		},
		{
			desc: "missing password",
			envVars: map[string]string{
				"INWX_USERNAME": "123",
				"INWX_PASSWORD": "",
			},
			expected: "inwx: some credentials information are missing: INWX_PASSWORD",
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
		username string
		password string
		expected string
	}{
		{
			desc:     "success",
			username: "123",
			password: "456",
		},
		{
			desc:     "missing credentials",
			expected: "inwx: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.Username = test.username
			config.Password = test.password

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

func TestLivePresentAndCleanup(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	envTest.Apply(map[string]string{
		"INWX_SANDBOX": "true",
		"INWX_TTL":     "3600", // In sandbox mode, the minimum allowed TTL is 3600
	})
	defer envTest.RestoreEnv()

	provider, err := NewDNSProvider()
	require.NoError(t, err)

	err = provider.Present(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)

	// Verify that no error is thrown if record already exists
	err = provider.Present(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}
