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
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	applycorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	applymetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/internal/controller/feature"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util"
	utilfeature "github.com/jetstack/cert-manager/pkg/util/feature"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
)

var (
	certificateGvk = cmapi.SchemeGroupVersion.WithKind("Certificate")
)

// SecretsManager creates and updates secrets with certificate and key data.
type SecretsManager struct {
	secretClient coreclient.SecretsGetter
	secretLister corelisters.SecretLister

	// userAgent is the Kubernetes client's user agent. This is used for setting
	// the field manager when Applying Secrets.
	userAgent string

	// if true, Secret resources created by the controller will have an
	// 'owner reference' set, meaning when the Certificate is deleted, the
	// Secret resource will be automatically deleted.
	// This option is disabled by default.
	enableSecretOwnerReferences bool
}

// SecretData is a structure wrapping private key, Certificate and CA data
type SecretData struct {
	PrivateKey, Certificate, CA []byte
}

// NewSecretsManager returns a new SecretsManager. Setting
// enableSecretOwnerReferences to true will mean that secrets will be deleted
// when the corresponding Certificate is deleted.
func NewSecretsManager(
	secretClient coreclient.SecretsGetter,
	secretLister corelisters.SecretLister,
	restConfig *rest.Config,
	enableSecretOwnerReferences bool,
) *SecretsManager {
	return &SecretsManager{
		secretClient:                secretClient,
		secretLister:                secretLister,
		userAgent:                   util.PrefixFromUserAgent(restConfig.UserAgent),
		enableSecretOwnerReferences: enableSecretOwnerReferences,
	}
}

// UpdateData will ensure the Secret resource contains the given secret data as
// well as appropriate metadata using an Apply call.
// If the Secret resource does not exist, it will be created on Apply.
// UpdateData will also update deprecated annotations if they exist.
func (s *SecretsManager) UpdateData(ctx context.Context, crt *cmapi.Certificate, data SecretData) error {
	secret, err := s.getCertificateSecret(ctx, crt)
	if err != nil {
		return err
	}

	log := logf.FromContext(ctx).WithName("secrets_manager")
	log = logf.WithResource(log, secret)

	if err := s.setValues(crt, secret, data); err != nil {
		return err
	}

	// Build Secret apply configuration and options.
	applyOpts := metav1.ApplyOptions{FieldManager: s.userAgent}
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

	// Apply secret resource. Don't force apply first, so we can catch the error
	// and log it.
	_, err = s.secretClient.Secrets(secret.Namespace).Apply(ctx, applyCnf, applyOpts)
	if apierrors.IsConflict(err) {
		log.Error(err, "forcing apply due to field management conflict")
		applyOpts.Force = true
		_, err = s.secretClient.Secrets(secret.Namespace).Apply(ctx, applyCnf, applyOpts)
	}

	if err != nil {
		return fmt.Errorf("failed to apply secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}

	return err
}

// SecretCertificateAnnotations returns a map which should be set on all
// Certificate Secret's Annotations, containing information about the Issuer
// and Certificate.
func SecretCertificateAnnotations(crt *cmapi.Certificate, data SecretData) (map[string]string, error) {
	annotations := make(map[string]string)

	annotations[cmapi.CertificateNameKey] = crt.Name
	annotations[cmapi.IssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
	annotations[cmapi.IssuerKindAnnotationKey] = apiutil.IssuerKind(crt.Spec.IssuerRef)
	annotations[cmapi.IssuerGroupAnnotationKey] = crt.Spec.IssuerRef.Group

	// Only add certificate data if it exists
	if len(data.Certificate) > 0 {
		x509Cert, err := utilpki.DecodeX509CertificateBytes(data.Certificate)
		// TODO: handle InvalidData here?
		if err != nil {
			return nil, err
		}

		annotations[cmapi.CommonNameAnnotationKey] = x509Cert.Subject.CommonName
		annotations[cmapi.AltNamesAnnotationKey] = strings.Join(x509Cert.DNSNames, ",")
		annotations[cmapi.IPSANAnnotationKey] = strings.Join(utilpki.IPAddressesToString(x509Cert.IPAddresses), ",")
		annotations[cmapi.URISANAnnotationKey] = strings.Join(utilpki.URLsToString(x509Cert.URIs), ",")
	}

	return annotations, nil
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

	annotations, err := SecretCertificateAnnotations(crt, data)
	if err != nil {
		return fmt.Errorf("failed to build Secret annotations: %w", err)
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

	for k, v := range annotations {
		secret.Annotations[k] = v
	}

	return nil
}

// getCertificateSecret will return a secret which is ready for fields to be
// applied. Only the Secret Type will be persisted from the original Secret.
func (s *SecretsManager) getCertificateSecret(ctx context.Context, crt *cmapi.Certificate) (*corev1.Secret, error) {
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
		keystoreData, err := encodePKCS12Keystore(string(pw), data.PrivateKey, data.Certificate, data.CA)
		if err != nil {
			return fmt.Errorf("error encoding PKCS12 bundle: %w", err)
		}
		// always overwrite the keystore entry for now
		secret.Data[pkcs12SecretKey] = keystoreData

		if len(data.CA) > 0 {
			truststoreData, err := encodePKCS12Truststore(string(pw), data.CA)
			if err != nil {
				return fmt.Errorf("error encoding PKCS12 trust store bundle: %w", err)
			}
			// always overwrite the truststore entry
			secret.Data[pkcs12TruststoreKey] = truststoreData
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
		keystoreData, err := encodeJKSKeystore(pw, data.PrivateKey, data.Certificate, data.CA)
		if err != nil {
			return fmt.Errorf("error encoding JKS bundle: %w", err)
		}
		// always overwrite the keystore entry
		secret.Data[jksSecretKey] = keystoreData

		if len(data.CA) > 0 {
			truststoreData, err := encodeJKSTruststore(pw, data.CA)
			if err != nil {
				return fmt.Errorf("error encoding JKS trust store bundle: %w", err)
			}
			// always overwrite the keystore entry
			secret.Data[jksTruststoreKey] = truststoreData
		}
	}

	return nil
}

// setAdditionalOutputFormat will set extra Secret Data keys with additional
// output formats according to any OutputFormats which have been configured.
func setAdditionalOutputFormats(crt *cmapi.Certificate, secret *corev1.Secret, data SecretData) error {
	for _, f := range crt.Spec.AdditionalOutputFormats {
		switch f.Type {
		case cmapi.CertificateOutputFormatDER:
			// Store binary format of the private key
			block, _ := pem.Decode(data.PrivateKey)
			secret.Data[cmapi.CertificateOutputFormatDERKey] = block.Bytes
		case cmapi.CertificateOutputFormatCombinedPEM:
			// Combine tls.key and tls.crt
			secret.Data[cmapi.CertificateOutputFormatCombinedPEMKey] = bytes.Join([][]byte{data.PrivateKey, data.Certificate}, []byte("\n"))
		default:
			return fmt.Errorf("unknown additional output format %s", format.Type)
		}
	}

	return nil
}
