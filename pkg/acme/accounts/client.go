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
	"crypto/rsa"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	acmeapi "golang.org/x/crypto/acme"

	acmecl "github.com/jetstack/cert-manager/pkg/acme/client"
	acmeutil "github.com/jetstack/cert-manager/pkg/acme/util"
	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/util"
)

// NewClient will return a new ACME client.
func NewClient(client *http.Client, config cmacme.ACMEIssuer, privateKey *rsa.PrivateKey) acmecl.Interface {
	return &acmeapi.Client{
		Key:          privateKey,
		HTTPClient:   client,
		DirectoryURL: config.Server,
		UserAgent:    util.CertManagerUserAgent,
		RetryBackoff: acmeutil.RetryBackoff,
	}
}

// BuildHTTPClient returns a instrumented HTTP client to be used by the ACME
// client.
// For the time being, we construct a new HTTP client on each invocation.
// This is because we need to set the 'skipTLSVerify' flag on the HTTP client
// itself.
// In future, we may change to having two global HTTP clients - one that ignores
// TLS connection errors, and the other that does not.
func BuildHTTPClient(metrics *metrics.Metrics, skipTLSVerify bool) *http.Client {
	return acmecl.NewInstrumentedClient(metrics,
		&http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: skipTLSVerify},
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
			Timeout: time.Second * 30,
		})
}
