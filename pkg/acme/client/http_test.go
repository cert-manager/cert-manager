/*
Copyright 2024 The cert-manager Authors.

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

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	fakeclock "k8s.io/utils/clock/testing"

	metricspkg "github.com/cert-manager/cert-manager/pkg/metrics"
)

func TestInstrumentedRoundTripper_LabelsAndAccumulation(t *testing.T) {
	testCases := []struct {
		name           string
		ctx            context.Context
		method         string
		statusToReturn int
		useTLS         bool
		requestsToMake int
		expectedAction string
	}{
		{
			name:           "GET 200 OK with action",
			ctx:            context.WithValue(context.Background(), AcmeActionLabel, "get_directory"),
			method:         "GET",
			statusToReturn: http.StatusOK,
			useTLS:         false,
			requestsToMake: 1,
			expectedAction: "get_directory",
		},
		{
			name:           "POST 500 Error without action",
			ctx:            context.Background(),
			method:         "POST",
			statusToReturn: http.StatusInternalServerError,
			useTLS:         false,
			requestsToMake: 1,
			expectedAction: "unnamed_action",
		},
		{
			name:           "GET 200 OK over HTTPS",
			ctx:            context.WithValue(context.Background(), AcmeActionLabel, "get_cert"),
			method:         "GET",
			statusToReturn: http.StatusOK,
			useTLS:         true,
			requestsToMake: 1,
			expectedAction: "get_cert",
		},
		{
			name:           "Multiple requests accumulate",
			ctx:            context.WithValue(context.Background(), AcmeActionLabel, "finalize_order"),
			method:         "POST",
			statusToReturn: http.StatusOK,
			useTLS:         false,
			requestsToMake: 3,
			expectedAction: "finalize_order",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixedClock := fakeclock.NewFakeClock(time.Now())
			metrics := metricspkg.New(testr.New(t), fixedClock)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusToReturn)
			})

			var server *httptest.Server
			var scheme string
			if tc.useTLS {
				server = httptest.NewTLSServer(handler)
				scheme = "https"
			} else {
				server = httptest.NewServer(handler)
				scheme = "http"
			}
			defer server.Close()

			httpClient := server.Client()
			instrumentedTransport := &Transport{
				wrappedRT: httpClient.Transport,
				metrics:   metrics,
			}
			httpClient.Transport = instrumentedTransport

			for range tc.requestsToMake {
				req, err := http.NewRequestWithContext(tc.ctx, tc.method, server.URL, nil)
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}

				// #nosec G704 -- test code using controlled httptest server
				resp, err := httpClient.Do(req)
				if err != nil {
					t.Fatalf("failed to make request: %v", err)
				}
				resp.Body.Close()
			}
			parsedURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("Failed to parse server URL: %v", err)
			}
			expectedCounter := fmt.Sprintf(`
				# HELP certmanager_http_acme_client_request_count Total number of outbound ACME HTTP requests. Labels: scheme (http/https), host (ACME host), action (logical ACME operation), method (HTTP verb), status (HTTP status code).
				# TYPE certmanager_http_acme_client_request_count counter
				certmanager_http_acme_client_request_count{action="%s",host="%s",method="%s",scheme="%s",status="%d"} %d
				`, tc.expectedAction, parsedURL.Host, tc.method, scheme, tc.statusToReturn, tc.requestsToMake)
			err = testutil.CollectAndCompare(metrics.ACMERequestCounter(), strings.NewReader(expectedCounter))
			if err != nil {
				t.Errorf("unexpected counter metric result:\n%v", err)
			}
		})
	}
}

// newInstrumentedTestClient returns an *http.Client for talking to a server whose
// transport is wrapped with the instrumented RoundTripper under test.
func newInstrumentedTestClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()

	fixedClock := fakeclock.NewFakeClock(time.Now())
	metrics := metricspkg.New(testr.New(t), fixedClock)

	httpClient := server.Client()
	httpClient.Transport = &Transport{
		wrappedRT: httpClient.Transport,
		metrics:   metrics,
	}
	return httpClient
}

func TestInstrumentedRoundTripper_CapsOversizedResponseBody(t *testing.T) {
	// The server attempts to stream far more than the limit allows,
	// mimicking a hostile ACME endpoint returning an unbounded body.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := bytes.Repeat([]byte("A"), 1<<20) // 1 MiB
		// Attempt to write more than maxACMEResponseBodyBytes.
		for range (maxACMEResponseBodyBytes / (1 << 20)) + 8 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	httpClient := newInstrumentedTestClient(t, server)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// #nosec G704 -- test code using controlled httptest server
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Reading past the limit surfaces a *http.MaxBytesError rather than truncating,
	// so an oversized body is a distinct, detectable condition. The
	// number of bytes delivered to the caller stays bounded by the limit
	// regardless of how much the server tried to send, keeping memory bounded.
	n, err := io.Copy(io.Discard, resp.Body)
	var maxBytesErr *http.MaxBytesError
	if !errors.As(err, &maxBytesErr) {
		t.Fatalf("expected a *http.MaxBytesError reading an oversized body, got %T: %v", err, err)
	}
	if n > maxACMEResponseBodyBytes {
		t.Errorf("read %d bytes from response body, expected it to be bounded by %d", n, maxACMEResponseBodyBytes)
	}
}

func TestInstrumentedRoundTripper_AllowsResponseBodyWithinLimit(t *testing.T) {
	// A body well within the limit (1 MiB) must be delivered in full.
	body := bytes.Repeat([]byte("A"), 1<<20)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck // test handler, response writer errors are not actionable
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	httpClient := newInstrumentedTestClient(t, server)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// #nosec G704 -- test code using controlled httptest server
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("unexpected error reading a within-limit body: %v", err)
	}
	if len(got) != len(body) {
		t.Errorf("read %d bytes, expected the full %d byte body", len(got), len(body))
	}
}
