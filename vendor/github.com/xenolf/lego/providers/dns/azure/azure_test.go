package azure

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

var envTest = tester.NewEnvTest(
	"AZURE_CLIENT_ID",
	"AZURE_CLIENT_SECRET",
	"AZURE_SUBSCRIPTION_ID",
	"AZURE_TENANT_ID",
	"AZURE_RESOURCE_GROUP").
	WithDomain("AZURE_DOMAIN")

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"AZURE_CLIENT_ID":       "A",
				"AZURE_CLIENT_SECRET":   "B",
				"AZURE_TENANT_ID":       "C",
				"AZURE_SUBSCRIPTION_ID": "D",
				"AZURE_RESOURCE_GROUP":  "E",
			},
		},
		{
			desc: "missing client ID",
			envVars: map[string]string{
				"AZURE_CLIENT_ID":       "",
				"AZURE_CLIENT_SECRET":   "B",
				"AZURE_TENANT_ID":       "C",
				"AZURE_SUBSCRIPTION_ID": "D",
				"AZURE_RESOURCE_GROUP":  "E",
			},
			expected: "failed to get oauth token from client credentials: parameter 'clientID' cannot be empty",
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
		desc           string
		clientID       string
		clientSecret   string
		subscriptionID string
		tenantID       string
		resourceGroup  string
		handler        func(w http.ResponseWriter, r *http.Request)
		expected       string
	}{
		{
			desc:           "success",
			clientID:       "A",
			clientSecret:   "B",
			tenantID:       "C",
			subscriptionID: "D",
			resourceGroup:  "E",
		},
		{
			desc:           "SubscriptionID missing",
			clientID:       "A",
			clientSecret:   "B",
			tenantID:       "C",
			subscriptionID: "",
			resourceGroup:  "",
			expected:       "azure: SubscriptionID is missing",
		},
		{
			desc:           "ResourceGroup missing",
			clientID:       "A",
			clientSecret:   "B",
			tenantID:       "C",
			subscriptionID: "D",
			resourceGroup:  "",
			expected:       "azure: ResourceGroup is missing",
		},
		{
			desc:           "use metadata",
			clientID:       "A",
			clientSecret:   "B",
			tenantID:       "C",
			subscriptionID: "",
			resourceGroup:  "",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte("foo"))
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.ClientID = test.clientID
			config.ClientSecret = test.clientSecret
			config.SubscriptionID = test.subscriptionID
			config.TenantID = test.tenantID
			config.ResourceGroup = test.resourceGroup

			handler := http.NewServeMux()
			server := httptest.NewServer(handler)
			defer server.Close()
			if test.handler == nil {
				handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
			} else {
				handler.HandleFunc("/", test.handler)
			}
			config.MetadataEndpoint = server.URL

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
