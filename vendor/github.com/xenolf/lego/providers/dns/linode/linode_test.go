package linode

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/timewasted/linode"
	"github.com/timewasted/linode/dns"
	"github.com/xenolf/lego/platform/tester"
)

type (
	apiResponse struct {
		Action string                 `json:"ACTION"`
		Data   interface{}            `json:"DATA"`
		Errors []linode.ResponseError `json:"ERRORARRAY"`
	}
	MockResponse struct {
		Response interface{}
		Errors   []linode.ResponseError
	}
	MockResponseMap map[string]MockResponse
)

var envTest = tester.NewEnvTest("LINODE_API_KEY")

func newMockServer(responses MockResponseMap) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure that we support the requested action.
		action := r.URL.Query().Get("api_action")
		resp, ok := responses[action]
		if !ok {
			http.Error(w, fmt.Sprintf("Unsupported mock action: %q", action), http.StatusInternalServerError)
			return
		}

		// Build the response that the server will return.
		response := apiResponse{
			Action: action,
			Data:   resp.Response,
			Errors: resp.Errors,
		}

		rawResponse, err := json.Marshal(response)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to JSON encode response: %v", err), http.StatusInternalServerError)
			return
		}

		// Send the response.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(rawResponse)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))

	time.Sleep(100 * time.Millisecond)
	return srv
}

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"LINODE_API_KEY": "123",
			},
		},
		{
			desc: "missing api key",
			envVars: map[string]string{
				"LINODE_API_KEY": "",
			},
			expected: "linode: some credentials information are missing: LINODE_API_KEY",
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
		apiKey   string
		expected string
	}{
		{
			desc:   "success",
			apiKey: "123",
		},
		{
			desc:     "missing credentials",
			expected: "linode: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.APIKey = test.apiKey

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

func TestDNSProvider_Present(t *testing.T) {
	defer envTest.RestoreEnv()
	os.Setenv("LINODE_API_KEY", "testing")

	p, err := NewDNSProvider()
	require.NoError(t, err)

	domain := "example.com"
	keyAuth := "dGVzdGluZw=="

	testCases := []struct {
		desc          string
		mockResponses MockResponseMap
		expectedError string
	}{
		{
			desc: "success",
			mockResponses: MockResponseMap{
				"domain.list": MockResponse{
					Response: []dns.Domain{
						{
							Domain:   domain,
							DomainID: 1234,
						},
					},
				},
				"domain.resource.create": MockResponse{
					Response: dns.ResourceResponse{
						ResourceID: 1234,
					},
				},
			},
		},
		{
			desc: "NoDomain",
			mockResponses: MockResponseMap{
				"domain.list": MockResponse{
					Response: []dns.Domain{{
						Domain:   "foobar.com",
						DomainID: 1234,
					}},
				},
			},
			expectedError: "dns: requested domain not found",
		},
		{
			desc: "CreateFailed",
			mockResponses: MockResponseMap{
				"domain.list": MockResponse{
					Response: []dns.Domain{
						{
							Domain:   domain,
							DomainID: 1234,
						},
					},
				},
				"domain.resource.create": MockResponse{
					Response: nil,
					Errors: []linode.ResponseError{
						{
							Code:    1234,
							Message: "Failed to create domain resource",
						},
					},
				},
			},
			expectedError: "Failed to create domain resource",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			server := newMockServer(test.mockResponses)
			defer server.Close()

			p.client.ToLinode().SetEndpoint(server.URL)

			err = p.Present(domain, "", keyAuth)
			if len(test.expectedError) == 0 {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}
		})
	}
}

func TestDNSProvider_CleanUp(t *testing.T) {
	defer envTest.RestoreEnv()
	os.Setenv("LINODE_API_KEY", "testing")

	p, err := NewDNSProvider()
	require.NoError(t, err)

	domain := "example.com"
	keyAuth := "dGVzdGluZw=="

	testCases := []struct {
		desc          string
		mockResponses MockResponseMap
		expectedError string
	}{
		{
			desc: "success",
			mockResponses: MockResponseMap{
				"domain.list": MockResponse{
					Response: []dns.Domain{
						{
							Domain:   domain,
							DomainID: 1234,
						},
					},
				},
				"domain.resource.list": MockResponse{
					Response: []dns.Resource{
						{
							DomainID:   1234,
							Name:       "_acme-challenge",
							ResourceID: 1234,
							Target:     "ElbOJKOkFWiZLQeoxf-wb3IpOsQCdvoM0y_wn0TEkxM",
							Type:       "TXT",
						},
					},
				},
				"domain.resource.delete": MockResponse{
					Response: dns.ResourceResponse{
						ResourceID: 1234,
					},
				},
			},
		},
		{
			desc: "NoDomain",
			mockResponses: MockResponseMap{
				"domain.list": MockResponse{
					Response: []dns.Domain{
						{
							Domain:   "foobar.com",
							DomainID: 1234,
						},
					},
				},
			},
			expectedError: "dns: requested domain not found",
		},
		{
			desc: "DeleteFailed",
			mockResponses: MockResponseMap{
				"domain.list": MockResponse{
					Response: []dns.Domain{
						{
							Domain:   domain,
							DomainID: 1234,
						},
					},
				},
				"domain.resource.list": MockResponse{
					Response: []dns.Resource{
						{
							DomainID:   1234,
							Name:       "_acme-challenge",
							ResourceID: 1234,
							Target:     "ElbOJKOkFWiZLQeoxf-wb3IpOsQCdvoM0y_wn0TEkxM",
							Type:       "TXT",
						},
					},
				},
				"domain.resource.delete": MockResponse{
					Response: nil,
					Errors: []linode.ResponseError{
						{
							Code:    1234,
							Message: "Failed to delete domain resource",
						},
					},
				},
			},
			expectedError: "Failed to delete domain resource",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			server := newMockServer(test.mockResponses)
			defer server.Close()

			p.client.ToLinode().SetEndpoint(server.URL)

			err = p.CleanUp(domain, "", keyAuth)
			if len(test.expectedError) == 0 {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}
		})
	}
}

func TestLivePresent(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("Skipping live test")
	}
	// TODO implement this test
}

func TestLiveCleanUp(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("Skipping live test")
	}
	// TODO implement this test
}
