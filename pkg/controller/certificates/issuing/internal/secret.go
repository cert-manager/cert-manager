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

package internal

import (
	"context"
	"crypto/x509"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	applycorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	applymetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/cert-manager/cert-manager/internal/controller/certificates"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

var (
	certificateGvk = cmapi.SchemeGroupVersion.WithKind("Certificate")
)

// SecretsManager creates and updates secrets with certificate and key data.
type SecretsManager struct {
	secretClient coreclient.SecretsGetter
	secretLister internalinformers.SecretLister

	// fieldManager is the manager name used for the Apply operations on Secrets.
	fieldManager string

	// if true, Secret resources created by the controller will have an
	// 'owner reference' set, meaning when the Certificate is deleted, the
	// Secret resource will be automatically deleted.
	// This option is disabled by default.
	enableSecretOwnerReferences bool
}

// SecretData is a structure wrapping private key, Certificate and CA data
type SecretData struct {
	PrivateKey, Certificate, CA         []byte
	CertificateName                     string
	IssuerName, IssuerKind, IssuerGroup string
}

// NewSecretsManager returns a new SecretsManager. Setting
// enableSecretOwnerReferences to true will mean that secrets will be deleted
// when the corresponding Certificate is deleted.
func NewSecretsManager(
	secretClient coreclient.SecretsGetter,
	secretLister internalinformers.SecretLister,
	fieldManager string,
	enableSecretOwnerReferences bool,
) *SecretsManager {
	return &SecretsManager{
		secretClient:                secretClient,
		secretLister:                secretLister,
		fieldManager:                fieldManager,
		enableSecretOwnerReferences: enableSecretOwnerReferences,
	}
}

// UpdateData will ensure the Secret resource contains the given secret data as
// well as appropriate metadata using an Apply call.
// If the Secret resource does not exist, it will be created on Apply.
// UpdateData will also update deprecated annotations if they exist.
func (s *SecretsManager) UpdateData(ctx context.Context, crt *cmapi.Certificate, data SecretData) error {
	secret, err := s.getCertificateSecret(crt)
	if err != nil {
		return err
	}

	log := logf.FromContext(ctx).WithName("secrets_manager")
	log = logf.WithResource(log, secret)

	if err := s.setValues(crt, secret, data); err != nil {
		return err
	}

	// Build Secret apply configuration and options.
	applyOpts := metav1.ApplyOptions{FieldManager: s.fieldManager, Force: true}
	applyCnf := applycorev1.Secret(secret.Name, secret.Namespace).
		WithAnnotations(secret.Annotations).WithLabels(secret.Labels).
		WithData(secret.Data).WithType(secret.Type)

	// If Secret owner reference is enabled, set it on the Secret. This results
	// in a no-op if the Secret already exists and has the owner reference set,
	// and visa-versa.
	if s.enableSecretOwnerReferences {
		ref := *metav1.NewControllerRef(crt, certificateGvk)
		applyCnf = applyCnf.WithOwnerReferences(&applymetav1.OwnerReferenceApplyConfiguration{
			APIVersion: &ref.APIVersion, Kind: &ref.Kind,
			Name: &ref.Name, UID: &ref.UID,
			Controller: ref.Controller, BlockOwnerDeletion: ref.BlockOwnerDeletion,
		})
	}

	log.V(logf.DebugLevel).Info("applying secret")

	_, err = s.secretClient.Secrets(secret.Namespace).Apply(ctx, applyCnf, applyOpts)
	if err != nil {
		return fmt.Errorf("failed to apply secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}

	return nil
}

// setValues will update the Secret resource 'secret' with the data contained
// in the given secretData.
// It will update labels and annotations on the Secret resource appropriately.
// The Secret resource 's' must be non-nil, although may be a resource that does
// not exist in the Kubernetes apiserver yet.
// setValues will NOT actually update the resource in the apiserver.
// It will also update depreciated issuer name and kind annotations if they
// exist.
func (s *SecretsManager) setValues(crt *cmapi.Certificate, secret *corev1.Secret, data SecretData) error {
	if err := s.setKeystores(crt, secret, data); err != nil {
		return fmt.Errorf("failed to add keystores to Secret: %w", err)
	}

	// Add additional output formats if feature enabled.
	if utilfeature.DefaultFeatureGate.Enabled(feature.AdditionalCertificateOutputFormats) {
		if err := setAdditionalOutputFormats(crt, secret, data); err != nil {
			return fmt.Errorf("failed to add additional output formats to Secret: %w", err)
		}
	}

	secret.Data[corev1.TLSPrivateKeyKey] = data.PrivateKey
	secret.Data[corev1.TLSCertKey] = data.Certificate
	if len(data.CA) > 0 {
		secret.Data[cmmeta.TLSCAKey] = data.CA
	}

	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}

	if secret.Labels == nil {
		secret.Labels = make(map[string]string)
	}

	if crt.Spec.SecretTemplate != nil {
		for k, v := range crt.Spec.SecretTemplate.Labels {
			secret.Labels[k] = v
		}
		for k, v := range crt.Spec.SecretTemplate.Annotations {
			secret.Annotations[k] = v
		}
	}

	var certificate *x509.Certificate
	if len(data.Certificate) > 0 {
		var err error
		certificate, err = utilpki.DecodeX509CertificateBytes(data.Certificate)
		// TODO: handle InvalidData here? Maybe we should still patch the secret
		// when we detect that the certificate bytes are invalid.
		if err != nil {
			return err
		}
	}

	certificateDetailsAnnotations, err := certificates.AnnotationsForCertificate(certificate)
	if err != nil {
		return err
	}
	for k, v := range certificateDetailsAnnotations {
		secret.Annotations[k] = v
	}

	// Add the certificate name and issuer details to the secret annotations.
	// If the annotations are not set/ empty, we do not use them to determine
	// if the secret needs to be updated.
	if data.CertificateName != "" {
		secret.Annotations[cmapi.CertificateNameKey] = data.CertificateName
	}
	if data.IssuerName != "" || data.IssuerKind != "" || data.IssuerGroup != "" {
		secret.Annotations[cmapi.IssuerNameAnnotationKey] = data.IssuerName
		secret.Annotations[cmapi.IssuerKindAnnotationKey] = data.IssuerKind
		secret.Annotations[cmapi.IssuerGroupAnnotationKey] = data.IssuerGroup
	}

	secret.Labels[cmapi.PartOfCertManagerControllerLabelKey] = "true"

	return nil
}

// getCertificateSecret will return a secret which is ready for fields to be
// applied. Only the Secret Type will be persisted from the original Secret.
func (s *SecretsManager) getCertificateSecret(crt *cmapi.Certificate) (*corev1.Secret, error) {
	// Get existing secret if it exists.
	existingSecret, err := s.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)

	// If secret doesn't exist yet, return an empty secret that should be
	// created.
	if apierrors.IsNotFound(err) {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crt.Spec.SecretName,
				Namespace: crt.Namespace,
			},
			Data: make(map[string][]byte),
			Type: corev1.SecretTypeTLS,
		}, nil
	}

	// Transient error.
	if err != nil {
		return nil, err
	}

	// Only copy Secret Type to not take ownership of annotations or labels on
	// Apply.
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crt.Spec.SecretName,
			Namespace: crt.Namespace,
		},
		Data: make(map[string][]byte),
		// Use the existing Secret's type since this may not be of type
		// `kubernetes.io/tls`, if for example it was created beforehand. Type is
		// immutable, so we must keep it to its original value.
		Type: existingSecret.Type,
	}, nil
}

// setKeystores will set extra Secret Data keys according to any Keystores
// which have been configured.
func (s *SecretsManager) setKeystores(crt *cmapi.Certificate, secret *corev1.Secret, data SecretData) error {
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
		profile := crt.Spec.Keystores.PKCS12.Profile
		keystoreData, err := encodePKCS12Keystore(profile, string(pw), data.PrivateKey, data.Certificate, data.CA)
		if err != nil {
			return fmt.Errorf("error encoding PKCS12 bundle: %w", err)
		}
		// always overwrite the keystore entry for now
		secret.Data[cmapi.PKCS12SecretKey] = keystoreData

		if len(data.CA) > 0 {
			truststoreData, err := encodePKCS12Truststore(profile, string(pw), data.CA)
			if err != nil {
				return fmt.Errorf("error encoding PKCS12 trust store bundle: %w", err)
			}
			// always overwrite the truststore entry
			secret.Data[cmapi.PKCS12TruststoreKey] = truststoreData
		}
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
		alias := "certificate"
		if crt.Spec.Keystores.JKS.Alias != nil {
			alias = *crt.Spec.Keystores.JKS.Alias
		}
		keystoreData, err := encodeJKSKeystore(pw, alias, data.PrivateKey, data.Certificate, data.CA)
		if err != nil {
			return fmt.Errorf("error encoding JKS bundle: %w", err)
		}
		// always overwrite the keystore entry
		secret.Data[cmapi.JKSSecretKey] = keystoreData

		if len(data.CA) > 0 {
			truststoreData, err := encodeJKSTruststore(pw, data.CA)
			if err != nil {
				return fmt.Errorf("error encoding JKS trust store bundle: %w", err)
			}
			// always overwrite the keystore entry
			secret.Data[cmapi.JKSTruststoreKey] = truststoreData
		}
	}

	return nil
}

// setAdditionalOutputFormat will set extra Secret Data keys with additional
// output formats according to any OutputFormats which have been configured.
func setAdditionalOutputFormats(crt *cmapi.Certificate, secret *corev1.Secret, data SecretData) error {
	for _, format := range crt.Spec.AdditionalOutputFormats {
		switch format.Type {
		case cmapi.CertificateOutputFormatDER:
			// Store binary format of the private key
			secret.Data[cmapi.CertificateOutputFormatDERKey] = certificates.OutputFormatDER(data.PrivateKey)
		case cmapi.CertificateOutputFormatCombinedPEM:
			// Combine tls.key and tls.crt
			secret.Data[cmapi.CertificateOutputFormatCombinedPEMKey] = certificates.OutputFormatCombinedPEM(data.PrivateKey, data.Certificate)
		default:
			return fmt.Errorf("unknown additional output format %s", format.Type)
		}
	}

	return nil
}
