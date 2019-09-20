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

package acme

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	acme "github.com/jetstack/cert-manager/pkg/acme/client"
	acmemw "github.com/jetstack/cert-manager/pkg/acme/client/middleware"
	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/util"
	acmecl "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

// This file implements a basic cache for ACME clients that can be used to
// obtain a reference to an ACME client.
// This can be accessed via the 'helper' defined in helper.go, or directly with
// the ClientWithKey function below.

// ClientWithKey will construct a new ACME client for the provided Issuer, using
// the given RSA private key.
func ClientWithKey(iss cmapi.GenericIssuer, pk *rsa.PrivateKey) (acme.Interface, error) {
	acmeSpec := iss.GetSpec().ACME
	if acmeSpec == nil {
		return nil, fmt.Errorf("issuer %q is not an ACME issuer. Ensure the 'acme' stanza is correctly specified on your Issuer resource", iss.GetObjectMeta().Name)
	}
	acmeCl := lookupClient(acmeSpec, pk)

	return acmemw.NewLogger(acmeCl), nil
}

// clientRepo is a collection of acme clients indexed
// by the options used to create them. This is used so
// that the cert-manager controllers can concurrently access
// the anti-replay nonces and directory information.
var (
	clientRepo   map[repoKey]*acmecl.Client
	clientRepoMu sync.Mutex
)

type repoKey struct {
	skiptls   bool
	server    string
	publickey string
	exponent  int
}

func lookupClient(spec *cmacme.ACMEIssuer, pk *rsa.PrivateKey) *acmecl.Client {
	clientRepoMu.Lock()
	defer clientRepoMu.Unlock()
	if clientRepo == nil {
		clientRepo = make(map[repoKey]*acmecl.Client)
	}
	repokey := repoKey{
		skiptls: spec.SkipTLSVerify,
		server:  spec.Server,
	}
	// Encoding a big.Int cannot fail
	pkbytes, _ := pk.PublicKey.N.GobEncode()
	repokey.publickey = string(pkbytes)
	repokey.exponent = pk.PublicKey.E

	client := clientRepo[repokey]
	if client != nil {
		return client
	}
	acmeCl := &acmecl.Client{
		HTTPClient:   buildHTTPClient(spec.SkipTLSVerify),
		Key:          pk,
		DirectoryURL: spec.Server,
		UserAgent:    util.CertManagerUserAgent,
	}
	clientRepo[repokey] = acmeCl
	return acmeCl
}

func ClearClientCache() {
	clientRepoMu.Lock()
	defer clientRepoMu.Unlock()
	clientRepo = nil
}

// buildHTTPClient returns an HTTP client to be used by the ACME client.
// For the time being, we construct a new HTTP client on each invocation.
// This is because we need to set the 'skipTLSVerify' flag on the HTTP client
// itself.
// In future, we may change to having two global HTTP clients - one that ignores
// TLS connection errors, and the other that does not.
func buildHTTPClient(skipTLSVerify bool) *http.Client {
	return acme.NewInstrumentedClient(&http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialTimeout,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: skipTLSVerify},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: time.Second * 30,
	})
}

var timeout = time.Duration(5 * time.Second)

func dialTimeout(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, addr)
}
