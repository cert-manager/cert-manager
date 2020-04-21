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

package issuing

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
)

type secretsManager struct {
	kubeClient   kubernetes.Interface
	secretLister corelisters.SecretLister

	// if true, Secret resources created by the controller will have an
	// 'owner reference' set, meaning when the Certificate is deleted, the
	// Secret resource will be automatically deleted.
	// This option is disabled by default.
	enableSecretOwnerReferences bool
}

// secretData is a structure wrapping private key, certificate and CA data
type secretData struct {
	sk, cert, ca []byte
}

func newSecretsManager(
	kubeClient kubernetes.Interface,
	secretLister corelisters.SecretLister,
	certificateControllerOptions controllerpkg.CertificateOptions,
) *secretsManager {
	return &secretsManager{
		kubeClient:                  kubeClient,
		secretLister:                secretLister,
		enableSecretOwnerReferences: certificateControllerOptions.EnableOwnerRef,
	}
}

// updateData will ensure the Secret resource contains the given secret
// data as well as appropriate metadata.
// If the Secret resource does not exist, it will be created.
// Otherwise, the existing resource will be updated.
// The first return argument will be true if the resource was updated/created
// without error.
// updateData will also update deprecated annotations if they exist.
func (s *secretsManager) updateData(ctx context.Context, crt *cmapi.Certificate, data secretData) error {
	// Fetch a copy of the existing Secret resource
	secret, err := s.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
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
				Namespace: crt.Namespace,
			},
			Type: corev1.SecretTypeTLS,
		}
	}

	// secret will be overwritten by 'existingSecret' if existingSecret is non-nil
	if s.enableSecretOwnerReferences {
		secret.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)}
	}

	err = s.setValues(crt, secret, data)
	if err != nil {
		return err
	}

	// If secret does not exist then create it
	if !secretExists {

		_, err = s.kubeClient.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
		return err
	}

	// Currently we are always updating. We should devise a way to not have to call an update if it is not necessary.
	_, err = s.kubeClient.CoreV1().Secrets(secret.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

// setValues will update the Secret resource 'secret' with the data contained
// in the given secretData.
// It will update labels and annotations on the Secret resource appropriately.
// The Secret resource 's' must be non-nil, although may be a resource that does
// not exist in the Kubernetes apiserver yet.
// setValues will NOT actually update the resource in the apiserver.
// If updating an existing Secret resource returned by an api client 'lister',
// make sure to DeepCopy the object first to avoid modifying data in-cache.
// It will also update depreciated issuer name and kind annotations if they exist.
func (s *secretsManager) setValues(crt *cmapi.Certificate, secret *corev1.Secret, data secretData) error {
	// initialize the `Data` field if it is nil
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}

	// Only write a new PKCS12/JKS file if any of the private key/certificate/CA
	// data has actually changed.
	if data.sk != nil && data.cert != nil &&
		(!bytes.Equal(secret.Data[corev1.TLSPrivateKeyKey], data.sk) ||
			!bytes.Equal(secret.Data[corev1.TLSCertKey], data.cert) ||
			!bytes.Equal(secret.Data[cmmeta.TLSCAKey], data.ca)) {

		// Handle the experimental PKCS12 support
		if crt.Spec.Keystores != nil && crt.Spec.Keystores.PKCS12 != nil && crt.Spec.Keystores.PKCS12.Create {
			ref := crt.Spec.Keystores.PKCS12.PasswordSecretRef
			pwSecret, err := s.secretLister.Secrets(crt.Namespace).Get(ref.Name)
			if err != nil {
				return fmt.Errorf("fetching PKCS12 keystore password from Secret: %v", err)
			}
			if pwSecret.Data == nil || len(pwSecret.Data[ref.Key]) == 0 {
				return fmt.Errorf("PKCS12 keystore password Secret contains no data for key %q", ref.Key)
			}
			pw := pwSecret.Data[ref.Key]
			keystoreData, err := encodePKCS12Keystore(string(pw), data.sk, data.cert, data.ca)
			if err != nil {
				return fmt.Errorf("error encoding PKCS12 bundle: %w", err)
			}
			// always overwrite the keystore entry for now
			secret.Data[pkcs12SecretKey] = keystoreData
		} else {
			delete(secret.Data, pkcs12SecretKey)
		}

		// Handle the experimental JKS support
		if crt.Spec.Keystores != nil && crt.Spec.Keystores.JKS != nil && crt.Spec.Keystores.JKS.Create {
			ref := crt.Spec.Keystores.JKS.PasswordSecretRef
			pwSecret, err := s.secretLister.Secrets(crt.Namespace).Get(ref.Name)
			if err != nil {
				return fmt.Errorf("fetching JKS keystore password from Secret: %v", err)
			}
			if pwSecret.Data == nil || len(pwSecret.Data[ref.Key]) == 0 {
				return fmt.Errorf("JKS keystore password Secret contains no data for key %q", ref.Key)
			}
			pw := pwSecret.Data[ref.Key]
			keystoreData, err := encodeJKSKeystore(pw, data.sk, data.cert, data.ca)
			if err != nil {
				return fmt.Errorf("error encoding JKS bundle: %w", err)
			}
			// always overwrite the keystore entry for now
			secret.Data[jksSecretKey] = keystoreData
		} else {
			delete(secret.Data, jksSecretKey)
		}
	}

	secret.Data[corev1.TLSPrivateKeyKey] = data.sk
	secret.Data[corev1.TLSCertKey] = data.cert
	secret.Data[cmmeta.TLSCAKey] = data.ca

	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}

	secret.Annotations[cmapi.CertificateNameKey] = crt.Name
	secret.Annotations[cmapi.IssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
	secret.Annotations[cmapi.IssuerKindAnnotationKey] = apiutil.IssuerKind(crt.Spec.IssuerRef)

	// If deprecated annotations exist with any value, then they too shall be
	// updated
	if _, ok := secret.Annotations[cmapi.DeprecatedIssuerNameAnnotationKey]; ok {
		secret.Annotations[cmapi.DeprecatedIssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
	}
	if _, ok := secret.Annotations[cmapi.DeprecatedIssuerKindAnnotationKey]; ok {
		secret.Annotations[cmapi.DeprecatedIssuerKindAnnotationKey] = apiutil.IssuerKind(crt.Spec.IssuerRef)
	}

	// if the certificate data is empty, clear the subject related annotations
	if len(data.cert) == 0 {
		delete(secret.Annotations, cmapi.CommonNameAnnotationKey)
		delete(secret.Annotations, cmapi.AltNamesAnnotationKey)
		delete(secret.Annotations, cmapi.IPSANAnnotationKey)
		delete(secret.Annotations, cmapi.URISANAnnotationKey)
	} else {
		x509Cert, err := utilpki.DecodeX509CertificateBytes(data.cert)
		// TODO: handle InvalidData here?
		if err != nil {
			return err
		}

		secret.Annotations[cmapi.CommonNameAnnotationKey] = x509Cert.Subject.CommonName
		secret.Annotations[cmapi.AltNamesAnnotationKey] = strings.Join(x509Cert.DNSNames, ",")
		secret.Annotations[cmapi.IPSANAnnotationKey] = strings.Join(utilpki.IPAddressesToString(x509Cert.IPAddresses), ",")
		secret.Annotations[cmapi.URISANAnnotationKey] = strings.Join(utilpki.URLsToString(x509Cert.URIs), ",")
	}

	return nil
}
