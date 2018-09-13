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

package kube

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	api "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func GetKeyPair(secretLister corelisters.SecretLister, namespace, name string) (certBytes []byte, keyBytes []byte, err error) {
	secret, err := secretLister.Secrets(namespace).Get(name)
	if err != nil {
		return nil, nil, err
	}

	var ok bool
	certBytes, ok = secret.Data[api.TLSCertKey]
	if !ok {
		return nil, nil, fmt.Errorf("no data for %q in secret '%s/%s'", api.TLSCertKey, namespace, name)
	}
	keyBytes, ok = secret.Data[api.TLSPrivateKeyKey]
	if !ok {
		return nil, nil, fmt.Errorf("no data for %q in secret '%s/%s'", api.TLSCertKey, namespace, name)
	}

	return certBytes, keyBytes, err
}

// SecretRSAKeyRef will decode a PKCS1 private key stored in a secret with
// 'name' in 'namespace'. It will read the private key data from the secret
// entry with name 'keyName'.
func SecretRSAKeyRef(secretLister corelisters.SecretLister, namespace, name, keyName string) (*rsa.PrivateKey, error) {
	privateKey, err := SecretTLSKeyRef(secretLister, namespace, name, api.TLSPrivateKeyKey)
	if err != nil {
		return nil, err
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("data for %q in secret '%s/%s' is not PKCS1 encoded", keyName, namespace, name)
	}

	return rsaPrivateKey, nil
}

// SecretRSAKey will decode a PKCS1 private key stored in a secret with
// 'name' in 'namespace'. It will read the private key data from the secret
// entry with name 'keyName'.
func SecretRSAKey(secretLister corelisters.SecretLister, namespace, name string) (*rsa.PrivateKey, error) {
	return SecretRSAKeyRef(secretLister, namespace, name, api.TLSPrivateKeyKey)
}

// SecretTLSKeyRef will decode a PKCS1/SEC1 (in effect, a RSA or ECDSA) private key stored in a
// secret with 'name' in 'namespace'. It will read the private key data from the secret
// entry with name 'keyName'.
func SecretTLSKeyRef(secretLister corelisters.SecretLister, namespace, name, keyName string) (crypto.PrivateKey, error) {
	secret, err := secretLister.Secrets(namespace).Get(name)
	if err != nil {
		return nil, err
	}

	keyBytes, ok := secret.Data[keyName]
	if !ok {
		return nil, fmt.Errorf("no data for %q in secret '%s/%s'", keyName, namespace, name)
	}
	key, err := pki.DecodePrivateKeyBytes(keyBytes)
	if err != nil {
		return key, errors.NewInvalidData(err.Error())
	}

	return key, nil
}

// SecretTLSKey will decode a PKCS1/SEC1 (in effect, a RSA or ECDSA) private key stored in a
// secret with 'name' in 'namespace'. It will read the private key data from the secret
// entry with name 'keyName'.
func SecretTLSKey(secretLister corelisters.SecretLister, namespace, name string) (crypto.PrivateKey, error) {
	return SecretTLSKeyRef(secretLister, namespace, name, api.TLSPrivateKeyKey)
}

func SecretTLSCert(secretLister corelisters.SecretLister, namespace, name string) (*x509.Certificate, error) {
	secret, err := secretLister.Secrets(namespace).Get(name)
	if err != nil {
		return nil, err
	}

	certBytes, ok := secret.Data[api.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("no data for %q in secret '%s/%s'", api.TLSCertKey, namespace, name)
	}
	cert, err := pki.DecodeX509CertificateBytes(certBytes)
	if err != nil {
		return cert, errors.NewInvalidData(err.Error())
	}

	return cert, nil
}
