/*
Copyright 2018 The Jetstack cert-manager contributors.

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
	"fmt"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var webhookRequestScenarios = map[string]struct {
	status    int
	payload   WebhookPayload
	timeout   time.Duration
	expectErr bool
}{
	"status 200": {
		status: http.StatusOK,
		payload: WebhookPayload{
			Operation:  presentOperation,
			Identifier: "_acme-challenge.example.com",
			Key:        "123",
			Metadata:   map[string]string{"test": "test"},
		},
		timeout:   0,
		expectErr: false,
	},
	"status 404": {
		status: http.StatusNotFound,
		payload: WebhookPayload{
			Operation:  presentOperation,
			Identifier: "_acme-challenge.example.com",
			Key:        "123",
			Metadata:   map[string]string{"test": "test"},
		},
		timeout:   0,
		expectErr: true,
	},
	"status 500": {
		status: http.StatusInternalServerError,
		payload: WebhookPayload{
			Operation:  presentOperation,
			Identifier: "_acme-challenge.example.com",
			Key:        "123",
			Metadata:   map[string]string{"test": "test"},
		},
		timeout:   0,
		expectErr: true,
	},
	"timeout": {
		status: http.StatusRequestTimeout,
		payload: WebhookPayload{
			Operation:  presentOperation,
			Identifier: "_acme-challenge.example.com",
			Key:        "123",
			Metadata:   map[string]string{"test": "test"},
		},
		timeout:   2 * time.Second,
		expectErr: true,
	},
}

type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func newFakeHTTPClient() *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: 200,
				Body:       ioutil.NopCloser(bytes.NewBufferString("OK")),
				// Must be set to non-nil value or it panics
				Header: make(http.Header),
			}
		}),
	}
}

func TestNewDNSProviderValid(t *testing.T) {
	_, err := NewDNSProvider("http://example.com/", map[string]string{"test": "test"}, false, []byte{}, util.RecursiveNameservers)
	assert.NoError(t, err)
}

func TestWebhookPresent(t *testing.T) {
	provider, err := NewDNSProvider("http://example.com/", map[string]string{"test": "test"}, false, []byte{}, util.RecursiveNameservers)
	assert.NoError(t, err)

	provider.httpClient = newFakeHTTPClient()
	err = provider.Present("example.com", "123", "123dda=")
	assert.NoError(t, err)
}

func TestWebhookCleanUp(t *testing.T) {
	provider, err := NewDNSProvider("http://example.com/", map[string]string{"test": "test"}, false, []byte{}, util.RecursiveNameservers)
	assert.NoError(t, err)

	provider.httpClient = newFakeHTTPClient()
	err = provider.CleanUp("example.com", "123", "123dda=")
	assert.NoError(t, err)
}

func TestWebhookRequest(t *testing.T) {
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

				assert.Equal(t, r.Method, "POST")

				body, err := ioutil.ReadAll(r.Body)
				assert.NoError(t, err)

				jsonPayload, err := json.Marshal(s.payload)
				assert.NoError(t, err)

				assert.Equal(t, body, jsonPayload)

				w.WriteHeader(s.status)
				fmt.Fprintln(w, jsonPayload)
			}))
			defer ts.Close()
			defer ts.CloseClientConnections()

			provider, err := NewDNSProvider(ts.URL, s.payload.Metadata, false, []byte{}, util.RecursiveNameservers)
			assert.NoError(t, err)

			provider.httpClient.Timeout = s.timeout

			err = provider.Present("example.com", s.payload.Identifier, s.payload.Key)
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
