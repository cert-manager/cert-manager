package linodev4

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/linode/linodego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/platform/tester"
)

type (
	MockResponseMap map[string]interface{}
)

var envTest = tester.NewEnvTest("LINODE_TOKEN")

func newMockServer(responses MockResponseMap) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure that we support the requested action.
		action := r.Method + ":" + r.URL.Path
		resp, ok := responses[action]
		if !ok {
			http.Error(w, fmt.Sprintf("Unsupported mock action: %q", action), http.StatusInternalServerError)
			return
		}

		rawResponse, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to JSON encode response: %v", err), http.StatusInternalServerError)
			return
		}

		// Send the response.
		w.Header().Set("Content-Type", "application/json")
		if err, ok := resp.(linodego.APIError); ok {
			if err.Errors[0].Reason == "Not found" {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		} else {
			w.WriteHeader(http.StatusOK)
		}

		_, err = w.Write(rawResponse)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
				"LINODE_TOKEN": "123",
			},
		},
		{
			desc: "missing api key",
			envVars: map[string]string{
				"LINODE_TOKEN": "",
			},
			expected: "linodev4: some credentials information are missing: LINODE_TOKEN",
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
			expected: "linodev4: Linode Access Token missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.Token = test.apiKey

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
	os.Setenv("LINODE_TOKEN", "testing")

	p, err := NewDNSProvider()
	require.NoError(t, err)
	require.NotNil(t, p)

	domain := "example.com"
	keyAuth := "dGVzdGluZw=="

	testCases := []struct {
		desc          string
		mockResponses MockResponseMap
		expectedError string
	}{
		{
			desc: "Success",
			mockResponses: MockResponseMap{
				"GET:/domains": linodego.DomainsPagedResponse{
					PageOptions: &linodego.PageOptions{
						Pages:   1,
						Results: 1,
						Page:    1,
					},
					Data: []linodego.Domain{{
						Domain: domain,
						ID:     1234,
					}},
				},
				"POST:/domains/1234/records": linodego.DomainRecord{
					ID: 1234,
				},
			},
		},
		{
			desc: "NoDomain",
			mockResponses: MockResponseMap{
				"GET:/domains": linodego.APIError{
					Errors: []linodego.APIErrorReason{{
						Reason: "Not found",
					}},
				},
			},
			expectedError: "[404] Not found",
		},
		{
			desc: "CreateFailed",
			mockResponses: MockResponseMap{
				"GET:/domains": &linodego.DomainsPagedResponse{
					PageOptions: &linodego.PageOptions{
						Pages:   1,
						Results: 1,
						Page:    1,
					},
					Data: []linodego.Domain{{
						Domain: "foobar.com",
						ID:     1234,
					}},
				},
				"POST:/domains/1234/records": linodego.APIError{
					Errors: []linodego.APIErrorReason{{
						Reason: "Failed to create domain resource",
						Field:  "somefield",
					}},
				},
			},
			expectedError: "[400] [somefield] Failed to create domain resource",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {

			server := newMockServer(test.mockResponses)
			defer server.Close()

			assert.NotNil(t, p.client)
			p.client.SetBaseURL(server.URL)

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
	os.Setenv("LINODE_TOKEN", "testing")

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
			desc: "Success",
			mockResponses: MockResponseMap{
				"GET:/domains": &linodego.DomainsPagedResponse{
					PageOptions: &linodego.PageOptions{
						Pages:   1,
						Results: 1,
						Page:    1,
					},
					Data: []linodego.Domain{{
						Domain: "foobar.com",
						ID:     1234,
					}},
				},
				"GET:/domains/1234/records": &linodego.DomainRecordsPagedResponse{
					PageOptions: &linodego.PageOptions{
						Pages:   1,
						Results: 1,
						Page:    1,
					},
					Data: []linodego.DomainRecord{{
						ID:     1234,
						Name:   "_acme-challenge",
						Target: "ElbOJKOkFWiZLQeoxf-wb3IpOsQCdvoM0y_wn0TEkxM",
						Type:   "TXT",
					}},
				},
				"DELETE:/domains/1234/records/1234": struct{}{},
			},
		},
		{
			desc: "NoDomain",
			mockResponses: MockResponseMap{
				"GET:/domains": linodego.APIError{
					Errors: []linodego.APIErrorReason{{
						Reason: "Not found",
					}},
				},
				"GET:/domains/1234/records": linodego.APIError{
					Errors: []linodego.APIErrorReason{{
						Reason: "Not found",
					}},
				},
			},
			expectedError: "[404] Not found",
		},
		{
			desc: "DeleteFailed",
			mockResponses: MockResponseMap{
				"GET:/domains": linodego.DomainsPagedResponse{
					PageOptions: &linodego.PageOptions{
						Pages:   1,
						Results: 1,
						Page:    1,
					},
					Data: []linodego.Domain{{
						ID:     1234,
						Domain: "example.com",
					}},
				},
				"GET:/domains/1234/records": linodego.DomainRecordsPagedResponse{
					PageOptions: &linodego.PageOptions{
						Pages:   1,
						Results: 1,
						Page:    1,
					},
					Data: []linodego.DomainRecord{{
						ID:     1234,
						Name:   "_acme-challenge",
						Target: "ElbOJKOkFWiZLQeoxf-wb3IpOsQCdvoM0y_wn0TEkxM",
						Type:   "TXT",
					}},
				},
				"DELETE:/domains/1234/records/1234": linodego.APIError{
					Errors: []linodego.APIErrorReason{{
						Reason: "Failed to delete domain resource",
					}},
				},
			},
			expectedError: "[400] Failed to delete domain resource",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			server := newMockServer(test.mockResponses)
			defer server.Close()

			p.client.SetBaseURL(server.URL)

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
