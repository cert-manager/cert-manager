/*
Copyright 2020 The cert-manager Authors.

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
	"time"

	"github.com/cert-manager/cert-manager/pkg/metrics"
)

// This file implements a custom instrumented HTTP client round tripper that
// exposes prometheus metrics for each endpoint called.
//
// We implement this as part of the HTTP client to ensure we don't miss any
// calls made to the ACME server caused by retries in the underlying ACME
// library.

// MetricsContextKey is the type used for context keys in the metrics package.
// Using a custom type prevents key collisions with other packages.
type MetricsContextKey string

// AcmeActionLabel is the context key for storing the logical ACME operation name.
const AcmeActionLabel = MetricsContextKey("acme_action")

// Transport is a http.RoundTripper that collects Prometheus metrics of every
// request it processes. It allows to be configured with callbacks that process
// request path and query into a suitable label value.
type Transport struct {
	metrics *metrics.Metrics

	wrappedRT http.RoundTripper
}

// NewInstrumentedClient takes a *http.Client and returns a *http.Client that
// has its RoundTripper wrapped with instrumentation.
func NewInstrumentedClient(metrics *metrics.Metrics, client *http.Client) *http.Client {
	// If next client is not defined we'll use http.DefaultClient.
	if client == nil {
		client = http.DefaultClient
	}

	if client.Transport == nil {
		client.Transport = http.DefaultTransport
	}

	client.Transport = &Transport{
		wrappedRT: client.Transport,
		metrics:   metrics,
	}

	return client
}

// RoundTrip implements http.RoundTripper. It forwards the request to the
// wrapped RoundTripper and measures the time it took in Prometheus summary.
func (it *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	statusCode := 999

	// Remember the current time.
	start := time.Now()

	// Make the request using the wrapped RoundTripper.
	resp, err := it.wrappedRT.RoundTrip(req)
	if resp != nil {
		statusCode = resp.StatusCode
	}
	var action string
	if op, ok := req.Context().Value(AcmeActionLabel).(string); ok {
		action = op
	} else {
		// Fallback for any requests where the context was not set.
		action = "unnamed_action"
	}
	labels := []string{
		req.URL.Scheme,
		req.URL.Host,
		action,
		req.Method,
		fmt.Sprintf("%d", statusCode),
	}
	// Observe the time it took to make the request.
	it.metrics.ObserveACMERequestDuration(time.Since(start), labels...)
	it.metrics.IncrementACMERequestCount(labels...)

	// return the response and error reported from the next RoundTripper.
	return resp, err
}
