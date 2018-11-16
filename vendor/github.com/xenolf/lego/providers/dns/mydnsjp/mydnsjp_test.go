package mydnsjp

import (
	"testing"
	"time"

	"github.com/xenolf/lego/platform/tester"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var envTest = tester.NewEnvTest("MYDNSJP_MASTER_ID", "MYDNSJP_PASSWORD").
	WithDomain("MYDNSJP_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"MYDNSJP_MASTER_ID": "test@example.com",
				"MYDNSJP_PASSWORD":  "123",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"MYDNSJP_MASTER_ID": "",
				"MYDNSJP_PASSWORD":  "",
			},
			expected: "mydnsjp: some credentials information are missing: MYDNSJP_MASTER_ID,MYDNSJP_PASSWORD",
		},
		{
			desc: "missing email",
			envVars: map[string]string{
				"MYDNSJP_MASTER_ID": "",
				"MYDNSJP_PASSWORD":  "key",
			},
			expected: "mydnsjp: some credentials information are missing: MYDNSJP_MASTER_ID",
		},
		{
			desc: "missing api key",
			envVars: map[string]string{
				"MYDNSJP_MASTER_ID": "awesome@possum.com",
				"MYDNSJP_PASSWORD":  "",
			},
			expected: "mydnsjp: some credentials information are missing: MYDNSJP_PASSWORD",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer envTest.RestoreEnv()
			envTest.ClearEnv()

			envTest.Apply(test.envVars)

			p, err := NewDNSProvider()

			if len(test.expected) == 0 {
				assert.NoError(t, err)
				assert.NotNil(t, p)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc     string
		masterID string
		password string
		expected string
	}{
		{
			desc:     "success",
			masterID: "test@example.com",
			password: "123",
		},
		{
			desc:     "missing credentials",
			expected: "mydnsjp: some credentials information are missing",
		},
		{
			desc:     "missing email",
			password: "123",
			expected: "mydnsjp: some credentials information are missing",
		},
		{
			desc:     "missing api key",
			masterID: "test@example.com",
			expected: "mydnsjp: some credentials information are missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.MasterID = test.masterID
			config.Password = test.password

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				assert.NoError(t, err)
				assert.NotNil(t, p)
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
	assert.NoError(t, err)
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
	assert.NoError(t, err)
}
