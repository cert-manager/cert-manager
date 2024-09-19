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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"

	vcert "github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
	"github.com/Venafi/vcert/v5/pkg/venafi/tpp"
	"github.com/go-logr/logr"
	"k8s.io/utils/ptr"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/api"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/pkg/util"
)

const (
	tppUsernameKey    = "username"
	tppPasswordKey    = "password"
	tppAccessTokenKey = "access-token"
	// Setting ClientId & Scope statically for simplicity
	tppClientId = "cert-manager.io"
	tppScopes   = "certificate:manage"

	defaultAPIKeyKey = "api-key"
)

type VenafiClientBuilder func(namespace string, secretsLister internalinformers.SecretLister,
	issuer cmapi.GenericIssuer, metrics *metrics.Metrics, logger logr.Logger, userAgent string) (Interface, error)

// Interface implements a Venafi client
type Interface interface {
	RequestCertificate(csrPEM []byte, duration time.Duration, customFields []api.CustomField) (string, error)
	RetrieveCertificate(pickupID string, csrPEM []byte, duration time.Duration, customFields []api.CustomField) ([]byte, error)
	Ping() error
	ReadZoneConfiguration() (*endpoint.ZoneConfiguration, error)
	SetClient(endpoint.Connector)
	VerifyCredentials() error
}

// Venafi is an implementation of vcert library to manager certificates from TPP or Venafi Cloud
type Venafi struct {
	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	namespace     string
	secretsLister internalinformers.SecretLister

	vcertClient connector
	tppClient   *tpp.Connector
	cloudClient *cloud.Connector
	config      *vcert.Config
}

// connector exposes a subset of the vcert Connector interface to make stubbing
// out its functionality during tests easier.
type connector interface {
	Ping() (err error)
	ReadZoneConfiguration() (config *endpoint.ZoneConfiguration, err error)
	RequestCertificate(req *certificate.Request) (requestID string, err error)
	RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error)
	// TODO: (irbekrm) this method is never used - can it be removed?
	RenewCertificate(req *certificate.RenewalRequest) (requestID string, err error)
}

// New constructs a Venafi client Interface. Errors may be network errors and
// should be considered for retrying.
func New(namespace string, secretsLister internalinformers.SecretLister, issuer cmapi.GenericIssuer, metrics *metrics.Metrics, logger logr.Logger, userAgent string) (Interface, error) {
	cfg, err := configForIssuer(issuer, secretsLister, namespace, userAgent)
	if err != nil {
		return nil, err
	}

	// Using `false` here ensures we do not immediately authenticate to the
	// Venafi backend. Doing so invokes a call which forces the use of APIKey
	// on the TPP side. This auth method has been removed since 22.4 of TPP.
	// This results in an APIKey usage error.
	// Reference code from vcert library which still refers to the APIKey.
	// ref: https://github.com/Venafi/vcert/blob/master/pkg/venafi/tpp/connector.go#L137-L146
	//
	// cert-manager uses the VerifyCredentials function below after the client
	// has been created.
	vcertClient, err := vcert.NewClient(cfg, false)
	if err != nil {
		return nil, fmt.Errorf("error creating Venafi client: %s", err.Error())
	}

	var tppc *tpp.Connector
	var cc *cloud.Connector

	switch vcertClient.GetType() {
	case endpoint.ConnectorTypeTPP:
		c, ok := vcertClient.(*tpp.Connector)
		if ok {
			tppc = c
		}
	case endpoint.ConnectorTypeCloud:
		c, ok := vcertClient.(*cloud.Connector)
		if ok {
			cc = c
		}
	}

	instrumentedVCertClient := newInstumentedConnector(vcertClient, metrics, logger)

	v := &Venafi{
		namespace:     namespace,
		secretsLister: secretsLister,
		vcertClient:   instrumentedVCertClient,
		cloudClient:   cc,
		tppClient:     tppc,
		config:        cfg,
	}

	// Since we did not authenticate when creating the client, authenticate
	// now to verify the credentials passed. Ensure that upon leaving this
	// function that credentials have been verified.
	if err := v.VerifyCredentials(); err != nil {
		return nil, err
	}
	return v, nil
}

// configForIssuer will convert a cert-manager Venafi issuer into a vcert.Config
// that can be used to instantiate an API client.
func configForIssuer(iss cmapi.GenericIssuer, secretsLister internalinformers.SecretLister, namespace string, userAgent string) (*vcert.Config, error) {
	venCfg := iss.GetSpec().Venafi

	switch {
	case venCfg.TPP != nil:
		tpp := venCfg.TPP
		tppSecret, err := secretsLister.Secrets(namespace).Get(tpp.CredentialsRef.Name)
		if err != nil {
			return nil, err
		}

		caBundle, err := caBundleForVcertTPP(tpp, secretsLister, namespace)
		if err != nil {
			return nil, err
		}

		username := string(tppSecret.Data[tppUsernameKey])
		password := string(tppSecret.Data[tppPasswordKey])
		accessToken := string(tppSecret.Data[tppAccessTokenKey])

		return &vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       tpp.URL,
			Zone:          venCfg.Zone,
			// always enable verbose logging for now
			LogVerbose: true,
			// We supply the CA bundle here, to trigger the vcert's builtin
			// validation of the supplied PEM content.
			// This is somewhat redundant because the value (if valid) will be
			// ignored by vcert since we also supply a custom HTTP client,
			// below. But we want to retain the CA bundle validation errors that
			// were returned in previous versions of this code.
			// https://github.com/Venafi/vcert/blob/89645a7710a7b529765274cb60dc5e28066217a1/client.go#L55-L61
			ConnectionTrust: string(caBundle),
			Credentials: &endpoint.Authentication{
				User:        username,
				Password:    password,
				AccessToken: accessToken,
			},
			Client: httpClientForVcert(&httpClientForVcertOptions{
				UserAgent:               ptr.To(userAgent),
				CABundle:                caBundle,
				TLSRenegotiationSupport: ptr.To(tls.RenegotiateOnceAsClient),
			}),
		}, nil
	case venCfg.Cloud != nil:
		cloud := venCfg.Cloud
		cloudSecret, err := secretsLister.Secrets(namespace).Get(cloud.APITokenSecretRef.Name)
		if err != nil {
			return nil, err
		}

		k := defaultAPIKeyKey
		if cloud.APITokenSecretRef.Key != "" {
			k = cloud.APITokenSecretRef.Key
		}
		apiKey := string(cloudSecret.Data[k])

		return &vcert.Config{
			ConnectorType: endpoint.ConnectorTypeCloud,
			BaseUrl:       cloud.URL,
			Zone:          venCfg.Zone,
			// always enable verbose logging for now
			LogVerbose: true,
			Credentials: &endpoint.Authentication{
				APIKey: apiKey,
			},
			Client: httpClientForVcert(&httpClientForVcertOptions{
				UserAgent: ptr.To(userAgent),
			}),
		}, nil
	}
	// API validation in webhook and in the ClusterIssuer and Issuer controller
	// Sync functions should make this unreachable in production.
	return nil, fmt.Errorf("neither Venafi Cloud or TPP configuration found")
}

// httpClientForVcertOptions contains options for `httpClientForVcert`, to allow
// you to customize the HTTP client.
type httpClientForVcertOptions struct {
	// UserAgent will add a User-Agent header to all HTTP requests.
	UserAgent *string
	// CABundle will override the CA certificates used to verify server
	// certificates.
	CABundle []byte
	// TLSRenegotiationSupport will override the TLSRenegotiationSupport setting
	// of the client.
	TLSRenegotiationSupport *tls.RenegotiationSupport
}

// httpClientForVcert creates an HTTP client which matches the default HTTP client of vcert,
// but allows you to customize client TLS renegotiation, and User-Agent.
//
// Why is it necessary to create our own HTTP client for vcert?
//
//  1. We need to customize the client TLS renegotiation setting when connecting
//     to certain TPP servers.
//  2. We need to customize the User-Agent header for all HTTP requests to Venafi
//     REST API endpoints.
//  3. The vcert package does not currently provide an easier way to change those
//     settings. See:
//     * https://github.com/Venafi/vcert/issues/437
//     * https://github.com/Venafi/vcert/issues/438
//
// Why is it necessary to customize the client TLS renegotiation?
//
//  1. The TPP API server is served by Microsoft Windows Server and IIS.
//  2. IIS uses TLS-1.2 by default[1] and it uses a
//     TLS-1.2 feature called "renegotiation" to allow client certificate
//     settings to be configured at the folder level. e.g.
//     https://tpp.example.com/vedauth may Require or Accept client
//     certificates while https://tpp.example.com/vedsdk may Ignore
//     client certificates.
//  3. When IIS is configured this way it behaves as follows[2]:
//     "Server receives a connection request on port 443; it begins a
//     handshake. The server does not ask for a client certificate. Once
//     the handshake is completed, the client sends the actual target URL
//     as a HTTP request in the SSL tunnel. Up to that point, the server
//     did not know which page was targeted; it only knew, at best, the
//     intended server name (through the Server Name Indication). Now
//     that the server knows which page is targeted, he knows which
//     "site" (i.e. part of the server, in IIS terminology) is to be
//     used."
//  4. In this scenario, the Go HTTP client MUST be configured to
//     renegotiate (by default it will refuse to renegotiate).
//     We use RenegotiateOnceAsClient rather than RenegotiateFreelyAsClient
//     because cert-manager establishes a new HTTPS connection for each API
//     request and therefore should only ever need to renegotiate once in this
//     scenario.
//
// Why do we supply CA bundle in the HTTP client **and** in the vcert.Config?
//
//  1. Overriding the HTTP client causes vcert to ignore the
//     `vcert.Config.ConnectionTrust` field, so we also have to set up the root
//     CA trust pool ourselves.
//  2. And the value of RootCAs MUST be nil unless the user has supplied a
//     custom CA, because a nil value causes the Go HTTP client to load the
//     system default root CAs.
//
// [1] TLS protocol version support in Microsoft Windows: https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-#tls-protocol-version-support
// [2] Should I use SSL/TLS renegotiation?: https://security.stackexchange.com/a/24569
func httpClientForVcert(options *httpClientForVcertOptions) *http.Client {
	// Copy vcert's default HTTP transport, which is mostly identical to the
	// http.DefaultTransport settings in Go's stdlib.
	// https://github.com/Venafi/vcert/blob/89645a7710a7b529765274cb60dc5e28066217a1/pkg/venafi/tpp/tpp.go#L481-L513
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			// Note: This DualStack setting is copied from vcert but
			// deviates from the http.DefaultTransport in Go's stdlib.
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Copy vcert's initialization of the TLS client config
	tlsClientConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig.Clone()
	if tlsClientConfig == nil {
		tlsClientConfig = &tls.Config{}
	}
	if len(options.CABundle) > 0 {
		rootCAs := x509.NewCertPool()
		rootCAs.AppendCertsFromPEM(options.CABundle)
		tlsClientConfig.RootCAs = rootCAs
	}
	transport.TLSClientConfig = tlsClientConfig

	if options.TLSRenegotiationSupport != nil {
		transport.TLSClientConfig.Renegotiation = *options.TLSRenegotiationSupport
	}

	var roundTripper http.RoundTripper = transport
	if options.UserAgent != nil {
		roundTripper = util.UserAgentRoundTripper(transport, *options.UserAgent)
	}

	// Copy vcert's initialization of the HTTP client, which overrides the default timeout.
	// https://github.com/Venafi/vcert/blob/89645a7710a7b529765274cb60dc5e28066217a1/pkg/venafi/tpp/tpp.go#L481-L513
	return &http.Client{
		Transport: roundTripper,
		Timeout:   time.Second * 30,
	}
}

// caBundleForVcertTPP is used to by ConnectionTrust and Client fields of vcert.Config.
// This function sets appropriate CA based on provided bundle or kubernetes secret
// If no custom CA bundle is configured, an empty byte slice is returned.
// Assumes exactly one of the in-line/Secret CA bundles are defined.
// If the `key` of the Secret CA bundle is not defined, its value defaults to
// `ca.crt`.
func caBundleForVcertTPP(tpp *cmapi.VenafiTPP, secretsLister internalinformers.SecretLister, namespace string) (caBundle []byte, err error) {
	if len(tpp.CABundle) > 0 {
		return tpp.CABundle, nil
	}

	secretRef := tpp.CABundleSecretRef
	if secretRef == nil {
		return nil, nil
	}

	var certBytes []byte
	var ok bool

	if secretRef != nil {
		secret, err := secretsLister.Secrets(namespace).Get(secretRef.Name)
		if err != nil {
			return nil, fmt.Errorf("could not access secret '%s/%s': %s", namespace, secretRef.Name, err)
		}

		var key string
		if secretRef.Key != "" {
			key = secretRef.Key
		} else {
			key = cmmeta.TLSCAKey
		}

		certBytes, ok = secret.Data[key]
		if !ok {
			return nil, fmt.Errorf("no data for %q in secret '%s/%s'", key, namespace, secretRef.Name)
		}

	}

	return certBytes, nil
}

func (v *Venafi) Ping() error {
	return v.vcertClient.Ping()
}

func (v *Venafi) ReadZoneConfiguration() (*endpoint.ZoneConfiguration, error) {
	return v.vcertClient.ReadZoneConfiguration()
}

func (v *Venafi) SetClient(client endpoint.Connector) {
	v.vcertClient = client
}

// VerifyCredentials will remotely verify the credentials for the client, both for TPP and Cloud
func (v *Venafi) VerifyCredentials() error {
	switch {
	case v.cloudClient != nil:
		err := v.cloudClient.Authenticate(&endpoint.Authentication{
			APIKey: v.config.Credentials.APIKey,
		})

		if err != nil {
			return fmt.Errorf("cloudClient.Authenticate: %v", err)
		}

		return nil
	case v.tppClient != nil:
		if v.config.Credentials == nil {
			return fmt.Errorf("credentials not configured")
		}

		if v.config.Credentials.AccessToken != "" {
			_, err := v.tppClient.VerifyAccessToken(&endpoint.Authentication{
				AccessToken: v.config.Credentials.AccessToken,
			})

			if err != nil {
				return fmt.Errorf("tppClient.VerifyAccessToken: %v", err)
			}

			return nil
		}

		if v.config.Credentials.User != "" && v.config.Credentials.Password != "" {
			// Use vcert library GetRefreshToken which brings back a token pair.
			// This includes the access_token which we set against the tppClient.
			// Replaces usage of v.tppClient.Authenticate function which would
			// have called the APIKey endpoint resulting in error.
			resp, err := v.tppClient.GetRefreshToken(&endpoint.Authentication{
				User:     v.config.Credentials.User,
				Password: v.config.Credentials.Password,
				ClientId: tppClientId,
				Scope:    tppScopes,
			})

			if err != nil {
				return fmt.Errorf("tppClient.GetRefreshToken: %v", err)
			}

			// Ensure that the access_token is stored on the tppClient object.
			err = v.tppClient.Authenticate(&endpoint.Authentication{
				AccessToken: resp.Access_token,
			})

			if err != nil {
				return fmt.Errorf("tppClient.Authenticate: %v", err)
			}

			return nil
		}
	}

	return fmt.Errorf("neither tppClient or cloudClient have been set")
}
