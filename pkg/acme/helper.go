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
	"crypto/rsa"
	"fmt"
	corelisters "k8s.io/client-go/listers/core/v1"

	acme "github.com/jetstack/cert-manager/pkg/acme/client"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmerrors "github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

type Helper interface {
	ClientForIssuer(iss cmapi.GenericIssuer) (acme.Interface, error)
	ReadPrivateKey(sel cmmeta.SecretKeySelector, ns string) (*rsa.PrivateKey, error)
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

// ReadPrivateKey will attempt to read and parse an ACME private key from a secret.
// If the referenced secret or key within that secret does not exist, an error will
// be returned.
// A *rsa.PrivateKey will be returned here, as ACME private keys can currently
// only be RSA.
func (h *helperImpl) ReadPrivateKey(sel cmmeta.SecretKeySelector, ns string) (*rsa.PrivateKey, error) {
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
