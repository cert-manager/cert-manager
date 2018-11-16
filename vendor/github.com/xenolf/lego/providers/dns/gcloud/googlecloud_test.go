package gcloud

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
)

var envTest = tester.NewEnvTest(
	"GCE_PROJECT",
	"GCE_SERVICE_ACCOUNT_FILE",
	"GOOGLE_APPLICATION_CREDENTIALS").
	WithDomain("GCE_DOMAIN").
	WithLiveTestExtra(func() bool {
		_, err := google.DefaultClient(context.Background(), dns.NdevClouddnsReadwriteScope)
		return err == nil
	})

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "invalid credentials",
			envVars: map[string]string{
				"GCE_PROJECT":              "123",
				"GCE_SERVICE_ACCOUNT_FILE": "",
				// as Travis run on GCE, we have to alter env
				"GOOGLE_APPLICATION_CREDENTIALS": "not-a-secret-file",
			},
			expected: "googlecloud: unable to get Google Cloud client: google: error getting credentials using GOOGLE_APPLICATION_CREDENTIALS environment variable: open not-a-secret-file: no such file or directory",
		},
		{
			desc: "missing project",
			envVars: map[string]string{
				"GCE_PROJECT":              "",
				"GCE_SERVICE_ACCOUNT_FILE": "",
			},
			expected: "googlecloud: project name missing",
		},
		{
			desc: "success",
			envVars: map[string]string{
				"GCE_PROJECT":              "",
				"GCE_SERVICE_ACCOUNT_FILE": "fixtures/gce_account_service_file.json",
			},
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
		project  string
		expected string
	}{
		{
			desc:     "invalid project",
			project:  "123",
			expected: "googlecloud: unable to create Google Cloud DNS service: client is nil",
		},
		{
			desc:     "missing project",
			expected: "googlecloud: unable to create Google Cloud DNS service: client is nil",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer envTest.RestoreEnv()
			envTest.ClearEnv()

			config := NewDefaultConfig()
			config.Project = test.project

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

	provider, err := NewDNSProviderCredentials(envTest.GetValue("GCE_PROJECT"))
	require.NoError(t, err)

	err = provider.Present(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}

func TestLivePresentMultiple(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()

	provider, err := NewDNSProviderCredentials(envTest.GetValue("GCE_PROJECT"))
	require.NoError(t, err)

	// Check that we're able to create multiple entries
	err = provider.Present(envTest.GetDomain(), "1", "123d==")
	require.NoError(t, err)

	err = provider.Present(envTest.GetDomain(), "2", "123d==")
	require.NoError(t, err)
}

func TestLiveCleanUp(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()

	provider, err := NewDNSProviderCredentials(envTest.GetValue("GCE_PROJECT"))
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}
