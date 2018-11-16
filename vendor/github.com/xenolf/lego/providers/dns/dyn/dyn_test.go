package dyn

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"DYN_CUSTOMER_NAME",
	"DYN_USER_NAME",
	"DYN_PASSWORD").
	WithDomain("DYN_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"DYN_CUSTOMER_NAME": "A",
				"DYN_USER_NAME":     "B",
				"DYN_PASSWORD":      "C",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"DYN_CUSTOMER_NAME": "",
				"DYN_USER_NAME":     "",
				"DYN_PASSWORD":      "",
			},
			expected: "dyn: some credentials information are missing: DYN_CUSTOMER_NAME,DYN_USER_NAME,DYN_PASSWORD",
		},
		{
			desc: "missing customer name",
			envVars: map[string]string{
				"DYN_CUSTOMER_NAME": "",
				"DYN_USER_NAME":     "B",
				"DYN_PASSWORD":      "C",
			},
			expected: "dyn: some credentials information are missing: DYN_CUSTOMER_NAME",
		},
		{
			desc: "missing password",
			envVars: map[string]string{
				"DYN_CUSTOMER_NAME": "A",
				"DYN_USER_NAME":     "",
				"DYN_PASSWORD":      "C",
			},
			expected: "dyn: some credentials information are missing: DYN_USER_NAME",
		},
		{
			desc: "missing username",
			envVars: map[string]string{
				"DYN_CUSTOMER_NAME": "A",
				"DYN_USER_NAME":     "B",
				"DYN_PASSWORD":      "",
			},
			expected: "dyn: some credentials information are missing: DYN_PASSWORD",
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
		customerName string
		password     string
		userName     string
		expected     string
	}{
		{
			desc:         "success",
			customerName: "A",
			password:     "B",
			userName:     "C",
		},
		{
			desc:     "missing credentials",
			expected: "dyn: credentials missing",
		},
		{
			desc:         "missing customer name",
			customerName: "",
			password:     "B",
			userName:     "C",
			expected:     "dyn: credentials missing",
		},
		{
			desc:         "missing password",
			customerName: "A",
			password:     "",
			userName:     "C",
			expected:     "dyn: credentials missing",
		},
		{
			desc:         "missing username",
			customerName: "A",
			password:     "B",
			userName:     "",
			expected:     "dyn: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.CustomerName = test.customerName
			config.Password = test.password
			config.UserName = test.userName

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
