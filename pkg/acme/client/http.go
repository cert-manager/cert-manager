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

package client

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jetstack/cert-manager/pkg/metrics"
)

// This file implements a custom instrumented HTTP client round tripper that
// exposes prometheus metrics for each endpoint called.
//
// We implement this as part of the HTTP client to ensure we don't miss any
// calls made to the ACME server caused by retries in the underlying ACME
// library.

// Transport is a http.RoundTripper that collects Prometheus metrics of every
// request it processes. It allows to be configured with callbacks that process
// request path and query into a suitable label value.
type Transport struct {
	next http.RoundTripper
}

// pathProcessor will trim the provided path to only include the first 2
// segments in order to reduce the number of prometheus labels generated
func pathProcessor(path string) string {
	p := strings.Split(path, "/")
	// only record the first two path segments as a prometheus label value
	if len(p) > 3 {
		p = p[:3]
	}
	return strings.Join(p, "/")
}

// RoundTrip implements http.RoundTripper. It forwards the request to the
// next RoundTripper and measures the time it took in Prometheus summary.
func (it *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	statusCode := 999

	// Remember the current time.
	now := time.Now()

	// Make the request using the next RoundTripper.
	resp, err := it.next.RoundTrip(req)
	if resp != nil {
		statusCode = resp.StatusCode
	}

	labels := []string{
		req.URL.Scheme,
		req.URL.Host,
		pathProcessor(req.URL.Path),
		req.Method,
		fmt.Sprintf("%d", statusCode),
	}
	// Observe the time it took to make the request.
	metrics.Default.ACMEClientRequestDurationSeconds.
		WithLabelValues(labels...).
		Observe(time.Since(now).Seconds())

	metrics.Default.ACMEClientRequestCount.
		WithLabelValues(labels...).Inc()

	// return the response and error reported from the next RoundTripper.
	return resp, err
}

// NewInstrumentedClient takes a *http.Client and returns a *http.Client that
// has its RoundTripper wrapped with instrumentation.
func NewInstrumentedClient(next *http.Client) *http.Client {
	// If next client is not defined we'll use http.DefaultClient.
	if next == nil {
		next = http.DefaultClient
	}

	next.Transport = newTransport(next.Transport)

	return next
}

// NewTransport takes a http.RoundTripper, wraps it with instrumentation and
// returns it as a new http.RoundTripper.
func newTransport(next http.RoundTripper) http.RoundTripper {
	// If next RoundTripper is not defined we'll use http.DefaultTransport.
	if next == nil {
		next = http.DefaultTransport
	}

	return &Transport{next: next}
}
