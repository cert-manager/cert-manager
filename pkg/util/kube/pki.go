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

package kube

import (
	"context"
	"crypto"
	"crypto/x509"

	corev1 "k8s.io/api/core/v1"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/errors"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// SecretTLSKeyRef will decode a PKCS1/SEC1 (in effect, a RSA or ECDSA) private key stored in a
// secret with 'name' in 'namespace'. It will read the private key data from the secret
// entry with name 'keyName'.
func SecretTLSKeyRef(ctx context.Context, secretLister internalinformers.SecretLister, namespace, name, keyName string) (crypto.Signer, error) {
	secret, err := secretLister.Secrets(namespace).Get(name)
	if err != nil {
		return nil, err
	}

	key, _, err := ParseTLSKeyFromSecret(secret, keyName)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// SecretTLSKey will decode a PKCS1/SEC1 (in effect, a RSA or ECDSA) private key stored in a
// secret with 'name' in 'namespace'. It will read the private key data from the secret
// entry with name 'keyName'.
func SecretTLSKey(ctx context.Context, secretLister internalinformers.SecretLister, namespace, name string) (crypto.Signer, error) {
	return SecretTLSKeyRef(ctx, secretLister, namespace, name, corev1.TLSPrivateKeyKey)
}

// ParseTLSKeyFromSecret will parse and decode a private key from the given
// Secret at the given key index.
func ParseTLSKeyFromSecret(secret *corev1.Secret, keyName string) (crypto.Signer, []byte, error) {
	keyBytes, ok := secret.Data[keyName]
	if !ok {
		return nil, nil, errors.NewInvalidData("no data for %q in secret '%s/%s'", keyName, secret.Namespace, secret.Name)
	}

	key, err := pki.DecodePrivateKeyBytes(keyBytes)
	if err != nil {
		return nil, keyBytes, errors.NewInvalidData(err.Error())
	}

	return key, keyBytes, nil
}

func SecretTLSCertChain(ctx context.Context, secretLister internalinformers.SecretLister, namespace, name string) ([]*x509.Certificate, error) {
	secret, err := secretLister.Secrets(namespace).Get(name)
	if err != nil {
		return nil, err
	}

	certBytes, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, errors.NewInvalidData("no data for %q in secret '%s/%s'", corev1.TLSCertKey, namespace, name)
	}

	cert, err := pki.DecodeX509CertificateChainBytes(certBytes)
	if err != nil {
		return cert, errors.NewInvalidData(err.Error())
	}

	return cert, nil
}

// SecretTLSKeyPairAndCA returns the X.509 certificate chain and private key of
// the leaf certificate contained in the target Secret. If the ca.crt field exists
// on the Secret, it is parsed and added to the end of the certificate chain.
func SecretTLSKeyPairAndCA(ctx context.Context, secretLister internalinformers.SecretLister, namespace, name string) ([]*x509.Certificate, crypto.Signer, error) {
	certs, key, err := SecretTLSKeyPair(ctx, secretLister, namespace, name)
	if err != nil {
		return nil, nil, err
	}

	secret, err := secretLister.Secrets(namespace).Get(name)
	if err != nil {
		return nil, nil, err
	}

	caBytes, ok := secret.Data[cmmeta.TLSCAKey]
	if !ok || len(caBytes) == 0 {
		return certs, key, nil
	}
	ca, err := pki.DecodeX509CertificateBytes(caBytes)
	if err != nil {
		return nil, key, errors.NewInvalidData(err.Error())
	}

	return append(certs, ca), key, nil
}

func SecretTLSKeyPair(ctx context.Context, secretLister internalinformers.SecretLister, namespace, name string) ([]*x509.Certificate, crypto.Signer, error) {
	secret, err := secretLister.Secrets(namespace).Get(name)
	if err != nil {
		return nil, nil, err
	}

	keyBytes, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, nil, errors.NewInvalidData("no private key data for %q in secret '%s/%s'", corev1.TLSPrivateKeyKey, namespace, name)
	}
	key, err := pki.DecodePrivateKeyBytes(keyBytes)
	if err != nil {
		return nil, nil, errors.NewInvalidData(err.Error())
	}

	certBytes, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, key, errors.NewInvalidData("no certificate data for %q in secret '%s/%s'", corev1.TLSCertKey, namespace, name)
	}
	cert, err := pki.DecodeX509CertificateChainBytes(certBytes)
	if err != nil {
		return nil, key, errors.NewInvalidData(err.Error())
	}

	return cert, key, nil
}

func SecretTLSCert(ctx context.Context, secretLister internalinformers.SecretLister, namespace, name string) (*x509.Certificate, error) {
	certs, err := SecretTLSCertChain(ctx, secretLister, namespace, name)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}
