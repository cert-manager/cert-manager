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

package accounts

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	"github.com/cert-manager/cert-manager/pkg/acme/client/middleware"
	acmeutil "github.com/cert-manager/cert-manager/pkg/acme/util"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	acmeapi "github.com/cert-manager/cert-manager/third_party/forked/acme"
)

const (
	// defaultACMEHTTPTimeout sets the default maximum time that an individual HTTP request can take when doing ACME operations.
	// Note that there may be other timeouts - e.g., dial timeouts or TLS handshake timeouts - which will be smaller than this. This
	// timeout is the overall timeout for the entire request.
	defaultACMEHTTPTimeout = time.Second * 90
)

type NewClientOptions struct {
	SkipTLSVerify bool
	CABundle      []byte
	Server        string
	PrivateKey    crypto.Signer
}

// NewClientFunc is a function type for building a new ACME client.
type NewClientFunc func(options NewClientOptions) acmecl.Interface

// NewClient is an implementation of NewClientFunc that returns a real ACME client.
func NewClient(
	metrics *metrics.Metrics,
	userAgent string,
) NewClientFunc {
	return func(options NewClientOptions) acmecl.Interface {
		httpClient := buildHTTPClientWithCABundle(metrics, options.SkipTLSVerify, options.CABundle)
		return newClientFromHTTPClient(httpClient, userAgent, options)
	}
}

func newClientFromHTTPClient(httpClient *http.Client, userAgent string, options NewClientOptions) acmecl.Interface {
	return middleware.NewLogger(&acmeapi.Client{
		Key:          options.PrivateKey,
		HTTPClient:   httpClient,
		DirectoryURL: options.Server,
		UserAgent:    userAgent,
		RetryBackoff: acmeutil.RetryBackoff,
	})
}

// buildHTTPClientWithCABundle returns an instrumented HTTP client to be used by an ACME
// client, with an optional custom CA bundle set.
// For the time being, we construct a new HTTP client on each invocation, because we need
// to set the 'skipTLSVerify' flag and the CA bundle on the HTTP client itself, distinct
// from the ACME client
func buildHTTPClientWithCABundle(metrics *metrics.Metrics, skipTLSVerify bool, caBundle []byte) *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipTLSVerify, // #nosec G402 -- false positive
	}

	// len also checks if the bundle is nil
	if len(caBundle) > 0 {
		pool := x509.NewCertPool()

		// We only want tlsConfig.RootCAs to be non-nil if we added at least one custom
		// CA to "pool".
		if ok := pool.AppendCertsFromPEM(caBundle); ok {
			tlsConfig.RootCAs = pool
		}
	}

	return acmecl.NewInstrumentedClient(
		metrics,
		&http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSClientConfig:       tlsConfig,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
			Timeout: defaultACMEHTTPTimeout,
		},
	)
}
