/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"

	"github.com/stretchr/testify/assert"
)

var webhookRequestScenarios = map[string]struct {
	httpStatus int
	response   v1alpha1.WebhookResponse
	payload    v1alpha1.WebhookPayload
	timeout    time.Duration
	expectErr  bool
}{
	"HTTP 200, status \"success\"": {
		httpStatus: 200,
		payload: v1alpha1.WebhookPayload{
			Operation: v1alpha1.WebhookPresentOperation,
			FQDN:      "_acme-challenge.example.com",
			Domain:    "_acme-challenge",
			Value:     "123",
			Metadata:  map[string]string{"test": "test"},
		},
		response: v1alpha1.WebhookResponse{
			Result: v1alpha1.WebhookResponseResultSuccess,
		},
		timeout:   0,
		expectErr: false,
	},
	"HTTP 200, status \"failure\", reason \"Mars Attacks!\"": {
		httpStatus: 200,
		payload: v1alpha1.WebhookPayload{
			Operation: v1alpha1.WebhookPresentOperation,
			FQDN:      "_acme-challenge.example.com",
			Domain:    "_acme-challenge",
			Value:     "123",
			Metadata:  map[string]string{"test": "test"},
		},
		response: v1alpha1.WebhookResponse{
			Result: v1alpha1.WebhookResponseResultSuccess,
			Reason: "Mars Attacks!",
		},
		timeout:   0,
		expectErr: false,
	},
	"HTTP 500, reason \"cosmic rays\"": {
		httpStatus: 200,
		payload: v1alpha1.WebhookPayload{
			Operation: v1alpha1.WebhookPresentOperation,
			FQDN:      "_acme-challenge.example.com",
			Domain:    "_acme-challenge",
			Value:     "123",
			Metadata:  map[string]string{"test": "test"},
		},
		response: v1alpha1.WebhookResponse{
			Result: v1alpha1.WebhookResponseResultFailure,
			Reason: "cosmic rays",
		},
		timeout:   0,
		expectErr: true,
	},
	"timeout": {
		httpStatus: 200,
		payload: v1alpha1.WebhookPayload{
			Operation: v1alpha1.WebhookPresentOperation,
			FQDN:      "_acme-challenge.example.com",
			Domain:    "_acme-challenge",
			Value:     "123",
			Metadata:  map[string]string{"test": "test"},
		},
		response: v1alpha1.WebhookResponse{
			Result: v1alpha1.WebhookResponseResultSuccess,
		},
		timeout:   2 * time.Second,
		expectErr: true,
	},
}

// the following machinery fakes a successful response
type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func newFakeHTTPClient() *http.Client {
	jsonBytes, _ := json.Marshal(v1alpha1.WebhookResponse{
		Result: "success",
	})

	return &http.Client{
		Transport: RoundTripFunc(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: 200,
				Body:       ioutil.NopCloser(bytes.NewReader(jsonBytes)),
				// Must be set to non-nil value or it panics
				Header: make(http.Header),
			}
		}),
	}
}

func TestNewDNSProviderValid(t *testing.T) {
	_, err := NewDNSProvider("http://example.com/", map[string]string{"test": "test"}, true, []byte{}, util.RecursiveNameservers)
	assert.NoError(t, err)
}

func TestWebhookFakePresent(t *testing.T) {
	provider, err := NewDNSProvider("http://example.com/", map[string]string{"test": "test"}, true, []byte{}, util.RecursiveNameservers)
	assert.NoError(t, err)

	provider.httpClient = newFakeHTTPClient()
	err = provider.Present("example.com", "123", "123dda=")
	assert.NoError(t, err)
}

func TestWebhookFakeCleanUp(t *testing.T) {
	provider, err := NewDNSProvider("http://example.com/", map[string]string{"test": "test"}, true, []byte{}, util.RecursiveNameservers)
	assert.NoError(t, err)

	provider.httpClient = newFakeHTTPClient()
	err = provider.CleanUp("example.com", "123", "123dda=")
	assert.NoError(t, err)
}

func TestWebhookSendPostFake(t *testing.T) {
	provider, err := NewDNSProvider("http://example.com/", map[string]string{"test": "test"}, true, []byte{}, util.RecursiveNameservers)
	assert.NoError(t, err)

	provider.httpClient = newFakeHTTPClient()
	httpResponse, err := sendPost(provider.httpClient, "http://example.com", []byte{})
	assert.NoError(t, err)

	jsonBytes, _ := json.Marshal(v1alpha1.WebhookResponse{
		Result: "success",
	})
	assert.Equal(t, jsonBytes, httpResponse.body)
	assert.Equal(t, 200, httpResponse.httpStatusCode)
}

func TestWebhookPresent(t *testing.T) {
	if testing.Short() == true {
		return
	}

	for n, s := range webhookRequestScenarios {
		t.Run(n, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if s.timeout != 0 {
					time.Sleep(s.timeout + 2*time.Second)
					return
				}

				assert.Equal(t, "POST", r.Method)

				body, err := ioutil.ReadAll(r.Body)
				assert.NoError(t, err)

				jsonPayload, err := json.Marshal(s.payload)
				assert.NoError(t, err)
				assert.Equal(t, jsonPayload, body)

				jsonResponse, err := json.Marshal(s.response)
				assert.NoError(t, err)

				w.WriteHeader(s.httpStatus)
				_, err = w.Write(jsonResponse)
				assert.NoError(t, err)
			}))
			defer ts.Close()
			defer ts.CloseClientConnections()

			provider, err := NewDNSProvider(ts.URL, s.payload.Metadata, true, []byte{}, util.RecursiveNameservers)
			assert.NoError(t, err)

			provider.httpClient.Timeout = s.timeout

			err = provider.Present(s.payload.Domain, s.payload.FQDN, s.payload.Value)
			if s.timeout != 0 {
				err, ok := err.(net.Error)
				assert.True(t, ok)
				assert.True(t, err.Timeout())
			} else if s.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

		})
	}
}
