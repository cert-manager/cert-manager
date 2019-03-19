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

	corev1 "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	acme "github.com/jetstack/cert-manager/pkg/acme/client"
	acmemw "github.com/jetstack/cert-manager/pkg/acme/client/middleware"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
	cmerrors "github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	acmecl "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

type Helper interface {
	ClientForIssuer(iss cmapi.GenericIssuer) (acme.Interface, error)
	ReadPrivateKey(sel cmapi.SecretKeySelector, ns string) (*rsa.PrivateKey, error)
}

// Helper is a structure that provides 'glue' between cert-managers API types and
// constructs, and ACME clients.
// For example, it can be used to obtain an ACME client for a IssuerRef that is
// correctly configured (e.g. with user agents, timeouts, proxy handling etc)
type helperImpl struct {
	SecretLister corelisters.SecretLister

	ClusterResourceNamespace string
}

var _ Helper = &helperImpl{}

// NewHelper is a helper that constructs a new Helper structure with the given
// secret lister.
func NewHelper(lister corelisters.SecretLister, ns string) Helper {
	return &helperImpl{
		SecretLister:             lister,
		ClusterResourceNamespace: ns,
	}
}

// PrivateKeySelector will default the SecretKeySelector with a default secret key
// if one is not already specified.
func PrivateKeySelector(sel cmapi.SecretKeySelector) cmapi.SecretKeySelector {
	if len(sel.Key) == 0 {
		sel.Key = corev1.TLSPrivateKeyKey
	}
	return sel
}

// ReadPrivateKey will attempt to read and parse an ACME private key from a secret.
// If the referenced secret or key within that secret does not exist, an error will
// be returned.
// A *rsa.PrivateKey will be returned here, as ACME private keys can currently
// only be RSA.
func (h *helperImpl) ReadPrivateKey(sel cmapi.SecretKeySelector, ns string) (*rsa.PrivateKey, error) {
	sel = PrivateKeySelector(sel)

	s, err := h.SecretLister.Secrets(ns).Get(sel.Name)
	if err != nil {
		return nil, err
	}

	data, ok := s.Data[sel.Key]
	if !ok {
		return nil, cmerrors.NewInvalidData("No secret data found for key %q in secret %q", sel.Key, sel.Name)
	}

	// DecodePrivateKeyBytes already wraps errors with NewInvalidData.
	pk, err := pki.DecodePrivateKeyBytes(data)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return nil, cmerrors.NewInvalidData("ACME private key in %q is not of type RSA", sel.Name)
	}

	return rsaKey, nil
}

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

// ClientForIssuer will return a properly configure ACME client for the given
// Issuer resource.
// If the private key for the Issuer does not exist, an error will be returned.
// If the provided issuer is not an ACME Issuer, an error will be returned.
func (h *helperImpl) ClientForIssuer(iss cmapi.GenericIssuer) (acme.Interface, error) {
	acmeSpec := iss.GetSpec().ACME
	if acmeSpec == nil {
		return nil, fmt.Errorf("issuer %q is not an ACME issuer. Ensure the 'acme' stanza is correctly specified on your Issuer resource", iss.GetObjectMeta().Name)
	}

	ns := iss.GetObjectMeta().Namespace
	if ns == "" {
		ns = h.ClusterResourceNamespace
	}

	pk, err := h.ReadPrivateKey(acmeSpec.PrivateKey, ns)
	if err != nil {
		return nil, err
	}

	return ClientWithKey(iss, pk)
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

func lookupClient(spec *cmapi.ACMEIssuer, pk *rsa.PrivateKey) *acmecl.Client {
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
