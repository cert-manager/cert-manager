// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/
package ovh

import (
	"os"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var (
	ovhEndpoint          string
	ovhApplicationKey    string
	ovhApplicationSecret string
	ovhConsumerKey       string
)

func init() {
	ovhEndpoint = os.Getenv("OVH_ENDPOINT")
	ovhApplicationKey = os.Getenv("OVH_APPLICATION_KEY")
	ovhApplicationSecret = os.Getenv("OVH_APPLICATION_SECRET")
	ovhConsumerKey = os.Getenv("OVH_CONSUMER_KEY")
}

var envTest = tester.NewEnvTest(
	"OVH_ENDPOINT",
	"OVH_APPLICATION_KEY",
	"OVH_APPLICATION_SECRET",
	"OVH_CONSUMER_KEY").
	WithDomain("OVH_DOMAIN")

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc              string
		apiEndpoint       string
		applicationKey    string
		applicationSecret string
		consumerKey       string
		expected          string
	}{
		{
			desc:              "success",
			apiEndpoint:       "ovh-eu",
			applicationKey:    "B",
			applicationSecret: "C",
			consumerKey:       "D",
		},
		{
			desc:     "missing credentials",
			expected: "ovh: credentials missing",
		},
		{
			desc:              "missing api endpoint",
			apiEndpoint:       "",
			applicationKey:    "B",
			applicationSecret: "C",
			consumerKey:       "D",
			expected:          "ovh: credentials missing",
		},
		{
			desc:              "missing invalid api endpoint",
			apiEndpoint:       "foobar",
			applicationKey:    "B",
			applicationSecret: "C",
			consumerKey:       "D",
			expected:          "ovh: unknown endpoint 'foobar', consider checking 'Endpoints' list of using an URL",
		},
		{
			desc:              "missing application key",
			apiEndpoint:       "ovh-eu",
			applicationKey:    "",
			applicationSecret: "C",
			consumerKey:       "D",
			expected:          "ovh: credentials missing",
		},
		{
			desc:              "missing application secret",
			apiEndpoint:       "ovh-eu",
			applicationKey:    "B",
			applicationSecret: "",
			consumerKey:       "D",
			expected:          "ovh: credentials missing",
		},
		{
			desc:              "missing consumer key",
			apiEndpoint:       "ovh-eu",
			applicationKey:    "B",
			applicationSecret: "C",
			consumerKey:       "",
			expected:          "ovh: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.APIEndpoint = test.apiEndpoint
			config.ApplicationKey = test.applicationKey
			config.ApplicationSecret = test.applicationSecret
			config.ConsumerKey = test.consumerKey

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.client)
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
	provider, err := NewDNSProvider(ovhEndpoint, ovhApplicationKey, ovhApplicationSecret, ovhConsumerKey, util.RecursiveNameservers)
	require.NoError(t, err)

	err = provider.Present(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}

func TestLiveCleanUp(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()
	provider, err := NewDNSProvider(ovhEndpoint, ovhApplicationKey, ovhApplicationSecret, ovhConsumerKey, util.RecursiveNameservers)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}
