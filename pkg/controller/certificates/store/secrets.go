/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package store

import (
	"encoding/pem"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller/certificates/codec"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

var managedDataKeys = []string{
	cmmeta.TLSCAKey,
	corev1.TLSCertKey,
	corev1.TLSPrivateKeyKey,
}

// SecretStore knows how to encode and decode bundles of PKI assets stored in
// Kubernetes Secret resources.
type SecretStore struct {
	// SecretLister used to read secrets
	Lister corelisters.SecretLister
	// Secret client used to write secrets
	NamespacedClient func(namespace string) typedcorev1.SecretInterface
	// If SetOwnerReferences is true, an owner reference will be set on Secret
	// resources when they are created.
	// This setting does not affect existing Secret resources.
	SetOwnerReferences bool
	// Encoder, if provided, is the encoder used for all encode operations.
	// If not specified, the correct encoder to use will be automatically
	// determined. This should only be set for testing purposes.
	Encoder codec.Encoder
}

func SecretCodecOptions(secret *corev1.Secret) codec.Options {
	opts := codec.Options{}
	if pkBytes, ok := secret.Data[corev1.TLSPrivateKeyKey]; ok {
		block, _ := pem.Decode(pkBytes)
		if block != nil {
			switch block.Type {
			case "PRIVATE KEY":
				opts.Format = codec.PKCS8Format
			case "EC PRIVATE KEY":
				opts.Format = codec.ECDSAFormat
			case "RSA PRIVATE KEY":
				opts.Format = codec.PKCS1Format
			}
		}
	}
	return opts
}

func CertificateCodecOptions(crt *cmapi.Certificate) codec.Options {
	switch crt.Spec.KeyEncoding {
	case "", cmapi.PKCS1:
		if crt.Spec.KeyAlgorithm == cmapi.ECDSAKeyAlgorithm {
			return codec.Options{Format: codec.ECDSAFormat}
		}
		return codec.Options{Format: codec.PKCS1Format}
	case cmapi.PKCS8:
		return codec.Options{Format: codec.PKCS8Format}
	}
	return codec.Options{}
}

func (s *SecretStore) Fetch(name, namespace string) (map[string]string, *codec.Bundle, error) {
	secret, err := s.Lister.Secrets(namespace).Get(name)
	if err != nil {
		return nil, nil, err
	}

	decoder, err := codec.NewCodec(SecretCodecOptions(secret))
	if err != nil {
		return nil, nil, errors.NewInvalidData(err.Error())
	}

	meta := secret.Annotations
	if meta == nil {
		meta = make(map[string]string)
	}
	b, err := decoder.Decode(codec.RawData{
		Data: secret.Data,
	})
	return meta, b, err
}

func (s *SecretStore) Store(name string, bundle codec.Bundle, crt *cmapi.Certificate, encoder codec.Encoder) error {
	var err error
	if encoder == nil {
		if s.Encoder == nil {
			encoder, err = codec.NewCodec(CertificateCodecOptions(crt))
			if err != nil {
				return err
			}
		} else {
			encoder = s.Encoder
		}
	}

	rawData, err := encoder.Encode(bundle)
	if err != nil {
		return err
	}

	secret, err := s.Lister.Secrets(crt.Namespace).Get(name)
	if apierrors.IsNotFound(err) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: crt.Namespace,
			},
			Type: corev1.SecretTypeTLS,
		}
		if s.SetOwnerReferences {
			secret.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate"))}
		}
		setSecretValues(crt, secret, bundle, *rawData, false)
		_, err := s.NamespacedClient(secret.Namespace).Create(secret)
		return err
	}
	if err != nil {
		return err
	}

	setSecretValues(crt, secret, bundle, *rawData, true)
	_, err = s.NamespacedClient(secret.Namespace).Update(secret)
	return err
}

func (s *SecretStore) EnsureMetadata(crt *cmapi.Certificate, b codec.Bundle) (bool, error) {
	secret, err := s.Lister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if err != nil {
		return false, err
	}

	newSecret := secret.DeepCopy()
	setSecretValues(crt, newSecret, b, codec.RawData{}, false)
	if reflect.DeepEqual(secret, newSecret) {
		return false, nil
	}
	_, err = s.NamespacedClient(secret.Namespace).Update(newSecret)
	return err == nil, err
}

// setSecretValues will update the Secret resource 's' with the data contained
// in the given secretData.
// It will update labels and annotations on the Secret resource appropriately.
// The Secret resource 's' must be non-nil, although may be a resource that does
// not exist in the Kubernetes apiserver yet.
// setSecretValues will NOT actually update the resource in the apiserver.
// If updating an existing Secret resource returned by an api client 'lister',
// make sure to DeepCopy the object first to avoid modifying data in-cache.
// It will also update depreciated issuer name and kind annotations if they exist.
func setSecretValues(crt *cmapi.Certificate, s *corev1.Secret, decoded codec.Bundle, encoded codec.RawData, prune bool) {
	if s.Data == nil {
		s.Data = make(map[string][]byte)
	}
	// prune existing 'managed keys' from Secret
	if prune {
		for _, k := range managedDataKeys {
			delete(s.Data, k)
		}
	}
	for k, v := range encoded.Data {
		s.Data[k] = v
	}

	if s.Annotations == nil {
		s.Annotations = make(map[string]string)
	}
	s.Annotations[cmapi.CertificateNameKey] = crt.Name
	s.Annotations[cmapi.IssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
	s.Annotations[cmapi.IssuerKindAnnotationKey] = apiutil.IssuerKind(crt.Spec.IssuerRef)

	// If deprecated annotations exist with any value, then they too shall be
	// updated
	if _, ok := s.Annotations[cmapi.DeprecatedIssuerNameAnnotationKey]; ok {
		s.Annotations[cmapi.DeprecatedIssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
	}
	if _, ok := s.Annotations[cmapi.DeprecatedIssuerKindAnnotationKey]; ok {
		s.Annotations[cmapi.DeprecatedIssuerKindAnnotationKey] = apiutil.IssuerKind(crt.Spec.IssuerRef)
	}

	// if the certificate data is empty, clear the subject related annotations
	if len(decoded.Certificates) == 0 {
		delete(s.Annotations, cmapi.CommonNameAnnotationKey)
		delete(s.Annotations, cmapi.AltNamesAnnotationKey)
		delete(s.Annotations, cmapi.IPSANAnnotationKey)
		delete(s.Annotations, cmapi.URISANAnnotationKey)
	} else {
		x509Cert := decoded.Certificates[0]
		s.Annotations[cmapi.CommonNameAnnotationKey] = x509Cert.Subject.CommonName
		s.Annotations[cmapi.AltNamesAnnotationKey] = strings.Join(x509Cert.DNSNames, ",")
		s.Annotations[cmapi.IPSANAnnotationKey] = strings.Join(pki.IPAddressesToString(x509Cert.IPAddresses), ",")
		s.Annotations[cmapi.URISANAnnotationKey] = strings.Join(pki.URLsToString(x509Cert.URIs), ",")
	}
}
