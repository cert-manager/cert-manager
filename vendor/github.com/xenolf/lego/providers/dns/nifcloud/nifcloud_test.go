package nifcloud

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"NIFCLOUD_ACCESS_KEY_ID",
	"NIFCLOUD_SECRET_ACCESS_KEY").
	WithDomain("NIFCLOUD_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"NIFCLOUD_ACCESS_KEY_ID":     "123",
				"NIFCLOUD_SECRET_ACCESS_KEY": "456",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"NIFCLOUD_ACCESS_KEY_ID":     "",
				"NIFCLOUD_SECRET_ACCESS_KEY": "",
			},
			expected: "nifcloud: some credentials information are missing: NIFCLOUD_ACCESS_KEY_ID,NIFCLOUD_SECRET_ACCESS_KEY",
		},
		{
			desc: "missing access key",
			envVars: map[string]string{
				"NIFCLOUD_ACCESS_KEY_ID":     "",
				"NIFCLOUD_SECRET_ACCESS_KEY": "456",
			},
			expected: "nifcloud: some credentials information are missing: NIFCLOUD_ACCESS_KEY_ID",
		},
		{
			desc: "missing secret key",
			envVars: map[string]string{
				"NIFCLOUD_ACCESS_KEY_ID":     "123",
				"NIFCLOUD_SECRET_ACCESS_KEY": "",
			},
			expected: "nifcloud: some credentials information are missing: NIFCLOUD_SECRET_ACCESS_KEY",
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
		accessKey string
		secretKey string
		expected  string
	}{
		{
			desc:      "success",
			accessKey: "123",
			secretKey: "456",
		},
		{
			desc:     "missing credentials",
			expected: "nifcloud: credentials missing",
		},
		{
			desc:      "missing api key",
			secretKey: "456",
			expected:  "nifcloud: credentials missing",
		},
		{
			desc:      "missing secret key",
			accessKey: "123",
			expected:  "nifcloud: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.AccessKey = test.accessKey
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

	time.Sleep(1 * time.Second)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}
