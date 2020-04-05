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

// This file defines methods used for PKCS#12 support.
// This is an experimental feature and the contents of this file are intended
// to be absorbed into a more fully fledged implementing ahead of the v0.15
// release.
// This should hopefully not exist by the next time you come to read this :)
package issuing

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
)

// secretData is a structure wrapping private key, certificate and CA data
type secretData struct {
	sk, cert, ca []byte
}

// updateSecretData will ensure the Secret resource contains the given secret
// data as well as appropriate metadata.
// If the Secret resource does not exist, it will be created.
// Otherwise, the existing resource will be updated.
// The first return argument will be true if the resource was updated/created
// without error.
// updateSecretData will also update deprecated annotations if they exist.
func (c *controller) updateSecretData(ctx context.Context, namespace string, crt *cmapi.Certificate, data secretData) error {
	// Fetch a copy of the existing Secret resource
	secret, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if !apierrors.IsNotFound(err) && err != nil {
		// If secret doesn't exist yet, then don't error
		return err
	}

	secretExists := (secret != nil)

	// If the seret does not exist yet, then we need to create one
	if !secretExists {
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crt.Spec.SecretName,
				Namespace: namespace,
			},
			Type: corev1.SecretTypeTLS,
		}
	}

	// secret will be overwritten by 'existingSecret' if existingSecret is non-nil
	if c.enableSecretOwnerReferences {
		secret.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)}
	}

	//newSecret := secret.DeepCopy()

	err = c.setSecretValues(crt, secret, data)
	if err != nil {
		return err
	}

	// TODO: P12/JKS values use a random parameter so it's values will always
	// change. Devise a better solution for checking change.
	//if reflect.DeepEqual(secret, newSecret) {
	//	return nil
	//}

	// If secret does not exist then create it
	if !secretExists {
		_, err = c.kubeClient.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
		return err
	}

	_, err = c.kubeClient.CoreV1().Secrets(secret.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
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
func (c *controller) setSecretValues(crt *cmapi.Certificate, s *corev1.Secret, data secretData) error {
	// initialize the `Data` field if it is nil
	if s.Data == nil {
		s.Data = make(map[string][]byte)
	}

	// Handle the experimental PKCS12 support
	if c.experimentalIssuePKCS12 {
		// Only write a new PKCS12 file if any of the private key/certificate/CA data has
		// actually changed.
		if data.sk != nil && data.cert != nil &&
			(!bytes.Equal(s.Data[corev1.TLSPrivateKeyKey], data.sk) ||
				!bytes.Equal(s.Data[corev1.TLSCertKey], data.cert) ||
				!bytes.Equal(s.Data[cmmeta.TLSCAKey], data.ca)) {
			keystoreData, err := encodePKCS12Keystore(c.experimentalPKCS12KeystorePassword, data.sk, data.cert, data.ca)
			if err != nil {
				return fmt.Errorf("error encoding PKCS12 bundle: %w", err)
			}
			// always overwrite the keystore entry for now
			s.Data[pkcs12SecretKey] = keystoreData
		}
	}
	// Handle the experimental JKS support
	if c.experimentalIssueJKS {
		// Only write a new JKS file if any of the private key/certificate/CA data has
		// actually changed.
		if data.sk != nil && data.cert != nil &&
			(!bytes.Equal(s.Data[corev1.TLSPrivateKeyKey], data.sk) ||
				!bytes.Equal(s.Data[corev1.TLSCertKey], data.cert) ||
				!bytes.Equal(s.Data[cmmeta.TLSCAKey], data.ca)) {
			keystoreData, err := encodeJKSKeystore(c.experimentalJKSPassword, data.sk, data.cert, data.ca)
			if err != nil {
				return fmt.Errorf("error encoding JKS bundle: %w", err)
			}
			// always overwrite the keystore entry for now
			s.Data[jksSecretKey] = keystoreData
		}
	}

	s.Data[corev1.TLSPrivateKeyKey] = data.sk
	s.Data[corev1.TLSCertKey] = data.cert
	s.Data[cmmeta.TLSCAKey] = data.ca

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
	if len(data.cert) == 0 {
		delete(s.Annotations, cmapi.CommonNameAnnotationKey)
		delete(s.Annotations, cmapi.AltNamesAnnotationKey)
		delete(s.Annotations, cmapi.IPSANAnnotationKey)
		delete(s.Annotations, cmapi.URISANAnnotationKey)
	} else {
		x509Cert, err := utilpki.DecodeX509CertificateBytes(data.cert)
		// TODO: handle InvalidData here?
		if err != nil {
			return err
		}

		s.Annotations[cmapi.CommonNameAnnotationKey] = x509Cert.Subject.CommonName
		s.Annotations[cmapi.AltNamesAnnotationKey] = strings.Join(x509Cert.DNSNames, ",")
		s.Annotations[cmapi.IPSANAnnotationKey] = strings.Join(utilpki.IPAddressesToString(x509Cert.IPAddresses), ",")
		s.Annotations[cmapi.URISANAnnotationKey] = strings.Join(utilpki.URLsToString(x509Cert.URIs), ",")
	}

	return nil
}
