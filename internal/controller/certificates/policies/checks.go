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

package policies

import (
	"bytes"
	"cmp"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"
	"sigs.k8s.io/structured-merge-diff/v4/value"

	cmmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
	internalcertificates "github.com/cert-manager/cert-manager/internal/controller/certificates"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func SecretDoesNotExist(input Input) (string, string, bool) {
	if input.Secret == nil {
		return DoesNotExist, "Issuing certificate as Secret does not exist", true
	}
	return "", "", false
}

func SecretIsMissingData(input Input) (string, string, bool) {
	if input.Secret.Data == nil {
		return MissingData, "Issuing certificate as Secret does not contain any data", true
	}
	pkData := input.Secret.Data[corev1.TLSPrivateKeyKey]
	certData := input.Secret.Data[corev1.TLSCertKey]
	if len(pkData) == 0 {
		return MissingData, "Issuing certificate as Secret does not contain a private key", true
	}
	if len(certData) == 0 {
		return MissingData, "Issuing certificate as Secret does not contain a certificate", true
	}
	return "", "", false
}

func SecretPublicKeysDiffer(input Input) (string, string, bool) {
	pk, err := pki.DecodePrivateKeyBytes(input.Secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return InvalidKeyPair, fmt.Sprintf("Issuing certificate as Secret contains invalid private key data: %v", err), true
	}
	x509Cert, err := pki.DecodeX509CertificateBytes(input.Secret.Data[corev1.TLSCertKey])
	if err != nil {
		return InvalidCertificate, fmt.Sprintf("Issuing certificate as Secret contains an invalid certificate: %v", err), true
	}

	equal, err := pki.PublicKeysEqual(x509Cert.PublicKey, pk.Public())
	if err != nil {
		return InvalidKeyPair, fmt.Sprintf("Secret contains an invalid key-pair: %v", err), true
	}
	if !equal {
		return InvalidKeyPair, "Issuing certificate as Secret contains a private key that does not match the certificate", true
	}

	return "", "", false
}

func SecretPrivateKeyMismatchesSpec(input Input) (string, string, bool) {
	pk, err := pki.DecodePrivateKeyBytes(input.Secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return InvalidKeyPair, fmt.Sprintf("Issuing certificate as Secret contains invalid private key data: %v", err), true
	}

	violations := pki.PrivateKeyMatchesSpec(pk, input.Certificate.Spec)
	if len(violations) > 0 {
		return SecretMismatch, fmt.Sprintf("Existing private key is not up to date for spec: %v", violations), true
	}
	return "", "", false
}

// SecretKeystoreFormatMismatch - When the keystore is not defined, the keystore
// related fields are removed from the secret.
// When one or more key stores are defined,  the
// corresponding secrets are generated.
// If the private key rotation is set to "Never", the key store related values are re-encoded
// as per the certificate specification
func SecretKeystoreFormatMismatch(input Input) (string, string, bool) {
	_, issuerProvidesCA := input.Secret.Data[cmmeta.TLSCAKey]

	if input.Certificate.Spec.Keystores == nil {
		if len(input.Secret.Data[cmapi.PKCS12SecretKey]) != 0 ||
			len(input.Secret.Data[cmapi.PKCS12TruststoreKey]) != 0 ||
			len(input.Secret.Data[cmapi.JKSSecretKey]) != 0 ||
			len(input.Secret.Data[cmapi.JKSTruststoreKey]) != 0 {
			return SecretMismatch, "Keystore is not defined", true
		}
		return "", "", false
	}

	if input.Certificate.Spec.Keystores.JKS != nil {
		if input.Certificate.Spec.Keystores.JKS.Create {
			if len(input.Secret.Data[cmapi.JKSSecretKey]) == 0 ||
				(len(input.Secret.Data[cmapi.JKSTruststoreKey]) == 0 && issuerProvidesCA) {
				return SecretMismatch, "JKS Keystore key does not contain data", true
			}
		} else {
			if len(input.Secret.Data[cmapi.JKSSecretKey]) != 0 ||
				len(input.Secret.Data[cmapi.JKSTruststoreKey]) != 0 {
				return SecretMismatch, "JKS Keystore create disabled", true
			}
		}
	} else {
		if len(input.Secret.Data[cmapi.JKSSecretKey]) != 0 ||
			len(input.Secret.Data[cmapi.JKSTruststoreKey]) != 0 {
			return SecretMismatch, "JKS Keystore not defined", true
		}
	}

	if input.Certificate.Spec.Keystores.PKCS12 != nil {
		if input.Certificate.Spec.Keystores.PKCS12.Create {
			if len(input.Secret.Data[cmapi.PKCS12SecretKey]) == 0 ||
				(len(input.Secret.Data[cmapi.PKCS12TruststoreKey]) == 0 && issuerProvidesCA) {
				return SecretMismatch, "PKCS12 Keystore key does not contain data", true
			}
		} else {
			if len(input.Secret.Data[cmapi.PKCS12SecretKey]) != 0 ||
				len(input.Secret.Data[cmapi.PKCS12TruststoreKey]) != 0 {
				return SecretMismatch, "PKCS12 Keystore create disabled", true
			}
		}
	} else {
		if len(input.Secret.Data[cmapi.PKCS12SecretKey]) != 0 ||
			len(input.Secret.Data[cmapi.PKCS12TruststoreKey]) != 0 {
			return SecretMismatch, "PKCS12 Keystore not defined", true
		}
	}

	return "", "", false
}

// SecretIssuerAnnotationsMismatch - When the issuer annotations are defined,
// it must match the issuer ref.
func SecretIssuerAnnotationsMismatch(input Input) (string, string, bool) {
	name, ok1 := input.Secret.Annotations[cmapi.IssuerNameAnnotationKey]
	kind, ok2 := input.Secret.Annotations[cmapi.IssuerKindAnnotationKey]
	group, ok3 := input.Secret.Annotations[cmapi.IssuerGroupAnnotationKey]
	if (ok1 || ok2 || ok3) && // only check if an annotation is present
		name != input.Certificate.Spec.IssuerRef.Name ||
		!issuerKindsEqual(kind, input.Certificate.Spec.IssuerRef.Kind) ||
		!issuerGroupsEqual(group, input.Certificate.Spec.IssuerRef.Group) {
		return IncorrectIssuer, fmt.Sprintf("Issuing certificate as Secret was previously issued by %q", formatIssuerRef(name, kind, group)), true
	}
	return "", "", false
}

// SecretCertificateNameAnnotationsMismatch - When the CertificateName annotation is defined,
// it must match the name of the Certificate.
func SecretCertificateNameAnnotationsMismatch(input Input) (string, string, bool) {
	name, ok := input.Secret.Annotations[cmapi.CertificateNameKey]
	if (ok) && // only check if an annotation is present
		name != input.Certificate.Name {
		return IncorrectCertificate, fmt.Sprintf("Secret was issued for %q. If this message is not transient, you might have two conflicting Certificates pointing to the same secret.", name), true
	}
	return "", "", false
}

// SecretPublicKeyDiffersFromCurrentCertificateRequest checks that the current CertificateRequest
// contains a CSR that is signed by the key stored in the Secret. A failure is often caused by the
// Secret being changed outside of the control of cert-manager, causing the current CertificateRequest
// to no longer match what is stored in the Secret.
func SecretPublicKeyDiffersFromCurrentCertificateRequest(input Input) (string, string, bool) {
	if input.CurrentRevisionRequest == nil {
		return "", "", false
	}
	pk, err := pki.DecodePrivateKeyBytes(input.Secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return InvalidKeyPair, fmt.Sprintf("Issuing certificate as Secret contains invalid private key data: %v", err), true
	}

	csr, err := pki.DecodeX509CertificateRequestBytes(input.CurrentRevisionRequest.Spec.Request)
	if err != nil {
		return InvalidCertificateRequest, fmt.Sprintf("Failed to decode current CertificateRequest: %v", err), true
	}

	equal, err := pki.PublicKeysEqual(csr.PublicKey, pk.Public())
	if err != nil {
		return InvalidCertificateRequest, fmt.Sprintf("CertificateRequest's public key is invalid: %v", err), true
	}
	if !equal {
		return SecretMismatch, "Secret contains a private key that does not match the current CertificateRequest", true
	}

	return "", "", false
}

func CurrentCertificateRequestMismatchesSpec(input Input) (string, string, bool) {
	if input.CurrentRevisionRequest == nil {
		// Fallback to comparing the Certificate spec with the issued certificate.
		// This case is encountered if the CertificateRequest that issued the current
		// Secret is not available (most likely due to it being deleted).
		// This comparison is a lot less robust than comparing against the CertificateRequest
		// as it has to tolerate/permit certain fields being overridden or ignored by the
		// signer/issuer implementation.
		return currentSecretValidForSpec(input)
	}

	violations, err := pki.RequestMatchesSpec(input.CurrentRevisionRequest, input.Certificate.Spec)
	if err != nil {
		// If parsing the request fails, we don't immediately trigger a re-issuance as
		// the existing certificate stored in the Secret may still be valid/up to date.
		return "", "", false
	}
	if len(violations) > 0 {
		return RequestChanged, fmt.Sprintf("Fields on existing CertificateRequest resource not up to date: %v", violations), true
	}

	return "", "", false
}

// currentSecretValidForSpec is not actually registered as part of the policy chain
// and is instead called by currentCertificateRequestValidForSpec if no there
// is no existing CertificateRequest resource.
func currentSecretValidForSpec(input Input) (string, string, bool) {
	x509Cert, err := pki.DecodeX509CertificateBytes(input.Secret.Data[corev1.TLSCertKey])
	if err != nil {
		return InvalidCertificate, fmt.Sprintf("Issuing certificate as Secret contains an invalid certificate: %v", err), true
	}
	// nolint: staticcheck // FuzzyX509AltNamesMatchSpec is used here for backwards compatibility
	violations := pki.FuzzyX509AltNamesMatchSpec(x509Cert, input.Certificate.Spec)
	if len(violations) > 0 {
		return SecretMismatch, fmt.Sprintf("Issuing certificate as Existing issued Secret is not up to date for spec: %v", violations), true
	}

	return "", "", false
}

// CurrentCertificateNearingExpiry returns a policy function that can be used to
// check whether an X.509 cert currently issued for a Certificate should be
// renewed.
func CurrentCertificateNearingExpiry(c clock.Clock) Func {
	return func(input Input) (string, string, bool) {
		x509Cert, err := pki.DecodeX509CertificateBytes(input.Secret.Data[corev1.TLSCertKey])
		if err != nil {
			return InvalidCertificate, fmt.Sprintf("Issuing certificate as Secret contains an invalid certificate: %v", err), true
		}

		// Determine if the certificate is nearing expiry solely by looking at
		// the actual cert, if it exists. We assume that at this point we have
		// called policy functions that check that input.Secret and
		// input.Secret.Data exists (SecretDoesNotExist and SecretIsMissingData).

		notBefore := metav1.NewTime(x509Cert.NotBefore)
		notAfter := metav1.NewTime(x509Cert.NotAfter)
		crt := input.Certificate
		renewalTime := pki.RenewalTime(notBefore.Time, notAfter.Time, crt.Spec.RenewBefore, crt.Spec.RenewBeforePercentage)

		renewIn := renewalTime.Time.Sub(c.Now())
		if renewIn > 0 {
			// renewal time is in the future, no need to renew
			return "", "", false
		}

		return Renewing, fmt.Sprintf("Renewing certificate as renewal was scheduled at %s", input.Certificate.Status.RenewalTime), true
	}
}

// CurrentCertificateHasExpired is used exclusively to check if the current
// issued certificate has actually expired rather than just nearing expiry.
func CurrentCertificateHasExpired(c clock.Clock) Func {
	return func(input Input) (string, string, bool) {
		x509Cert, err := pki.DecodeX509CertificateBytes(input.Secret.Data[corev1.TLSCertKey])
		if err != nil {
			return InvalidCertificate, fmt.Sprintf("Issuing certificate as Secret contains an invalid certificate: %v", err), true
		}

		if c.Now().After(x509Cert.NotAfter) {
			return Expired, fmt.Sprintf("Certificate expired on %s", x509Cert.NotAfter.Format(time.RFC1123)), true
		}
		return "", "", false
	}
}

func formatIssuerRef(name, kind, group string) string {
	if group == "" {
		group = "cert-manager.io"
	}
	if kind == "" {
		kind = "Issuer"
	}
	return fmt.Sprintf("%s.%s/%s", kind, group, name)
}

const defaultIssuerKind = "Issuer"
const defaultIssuerGroup = "cert-manager.io"

func issuerKindsEqual(l, r string) bool {
	if l == "" {
		l = defaultIssuerKind
	}
	if r == "" {
		r = defaultIssuerKind
	}
	return l == r
}

func issuerGroupsEqual(l, r string) bool {
	if l == "" {
		l = defaultIssuerGroup
	}
	if r == "" {
		r = defaultIssuerGroup
	}
	return l == r
}

// SecretSecretTemplateMismatch will inspect the given Secret's Annotations
// and Labels, and compare these maps against those that appear on the given
// Certificate's SecretTemplate.
// NOTE: This function only compares the values of annotations and labels that
// exist both in the Certificate's SecretTemplate and the Secret. Missing and
// extra annotations or labels are detected by the SecretManagedLabelsAndAnnotationsManagedFieldsMismatch
// and SecretSecretTemplateManagedFieldsMismatch functions instead.
func SecretSecretTemplateMismatch(input Input) (string, string, bool) {
	if input.Certificate.Spec.SecretTemplate == nil {
		return "", "", false
	}

	if match, _ := mapsHaveMatchingValues(input.Certificate.Spec.SecretTemplate.Annotations, input.Secret.Annotations); !match {
		return SecretTemplateMismatch, "Certificate's SecretTemplate Annotations missing or incorrect value on Secret", true
	}

	if match, _ := mapsHaveMatchingValues(input.Certificate.Spec.SecretTemplate.Labels, input.Secret.Labels); !match {
		return SecretTemplateMismatch, "Certificate's SecretTemplate Labels missing or incorrect value on Secret", true
	}

	return "", "", false
}

func certificateDataAnnotationsForSecret(secret *corev1.Secret) (annotations map[string]string, err error) {
	var certificate *x509.Certificate
	if len(secret.Data[corev1.TLSCertKey]) > 0 {
		certificate, err = pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
		if err != nil {
			return nil, err
		}
	}

	certificateAnnotations, err := internalcertificates.AnnotationsForCertificate(certificate)
	if err != nil {
		return nil, err
	}

	return certificateAnnotations, nil
}

func secretLabelsAndAnnotationsManagedFields(secret *corev1.Secret, fieldManager string) (labels, annotations sets.Set[string], err error) {
	managedLabels, managedAnnotations := sets.New[string](), sets.New[string]()

	for _, managedField := range secret.ManagedFields {
		// If the managed field isn't owned by the cert-manager controller, ignore.
		if managedField.Manager != fieldManager || managedField.FieldsV1 == nil {
			continue
		}

		// Decode the managed field.
		var fieldset fieldpath.Set
		if err := fieldset.FromJSON(bytes.NewReader(managedField.FieldsV1.Raw)); err != nil {
			return nil, nil, err
		}

		// Extract the labels and annotations of the managed fields.
		metadata := fieldset.Children.Descend(fieldpath.PathElement{
			FieldName: ptr.To("metadata"),
		})
		labels := metadata.Children.Descend(fieldpath.PathElement{
			FieldName: ptr.To("labels"),
		})
		annotations := metadata.Children.Descend(fieldpath.PathElement{
			FieldName: ptr.To("annotations"),
		})

		// Gather the annotations and labels on the managed fields. Remove the '.'
		// prefix which appears on managed field keys.
		labels.Iterate(func(path fieldpath.Path) {
			managedLabels.Insert(strings.TrimPrefix(path.String(), "."))
		})
		annotations.Iterate(func(path fieldpath.Path) {
			managedAnnotations.Insert(strings.TrimPrefix(path.String(), "."))
		})
	}

	return managedLabels, managedAnnotations, nil
}

// SecretManagedLabelsAndAnnotationsManagedFieldsMismatch will inspect the given Secret's
// managed fields for its Annotations and Labels, and compare this against the
// Labels and Annotations that are managed by cert-manager. Returns false if Annotations and
// Labels match on both the Certificate's SecretTemplate and the Secret's
// managed fields, true otherwise.
// Also returns true if the managed fields or signed certificate were not able
// to be decoded.
func SecretManagedLabelsAndAnnotationsManagedFieldsMismatch(fieldManager string) Func {
	return func(input Input) (string, string, bool) {
		managedLabels, managedAnnotations, err := secretLabelsAndAnnotationsManagedFields(input.Secret, fieldManager)
		if err != nil {
			return ManagedFieldsParseError, fmt.Sprintf("failed to decode managed fields on Secret: %s", err), true
		}

		// Remove the non cert-manager annotations from the managed Annotations so we can compare
		// 1 to 1 all the cert-manager annotations.
		for k := range managedAnnotations {
			if strings.HasPrefix(k, "cert-manager.io/") ||
				strings.HasPrefix(k, "controller.cert-manager.io/") {
				continue
			}

			delete(managedAnnotations, k)
		}

		// Ignore the CertificateName and IssuerRef annotations as these cannot be set by the postIssuance controller.
		managedAnnotations.Delete(
			cmapi.CertificateNameKey,       // SecretCertificateNameAnnotationMismatch checks the value
			cmapi.IssuerNameAnnotationKey,  // SecretIssuerAnnotationsMismatch checks the value
			cmapi.IssuerKindAnnotationKey,  // SecretIssuerAnnotationsMismatch checks the value
			cmapi.IssuerGroupAnnotationKey, // SecretIssuerAnnotationsMismatch checks the value
		)

		// Remove the non cert-manager labels from the managed labels so we can compare
		// 1 to 1 all the cert-manager labels.
		for k := range managedLabels {
			if strings.HasPrefix(k, "cert-manager.io/") ||
				strings.HasPrefix(k, "controller.cert-manager.io/") {
				continue
			}

			delete(managedLabels, k)
		}

		expCertificateDataAnnotations, err := certificateDataAnnotationsForSecret(input.Secret)
		if err != nil {
			return InvalidCertificate, fmt.Sprintf("Failed getting secret annotations: %v", err), true
		}

		expLabels := sets.New[string](
			cmapi.PartOfCertManagerControllerLabelKey, // SecretBaseLabelsMismatch checks the value
		)
		expAnnotations := sets.New[string]()
		for k := range expCertificateDataAnnotations { // SecretCertificateDetailsAnnotationsMismatch checks the value
			expAnnotations.Insert(k)
		}

		if !managedLabels.Equal(expLabels) {
			missingLabels := expLabels.Difference(managedLabels)
			if len(missingLabels) > 0 {
				return SecretManagedMetadataMismatch, fmt.Sprintf("Secret is missing these Managed Labels: %v", sets.List(missingLabels)), true
			}

			extraLabels := managedLabels.Difference(expLabels)
			return SecretManagedMetadataMismatch, fmt.Sprintf("Secret has these extra Labels: %v", sets.List(extraLabels)), true
		}

		if !managedAnnotations.Equal(expAnnotations) {
			missingAnnotations := expAnnotations.Difference(managedAnnotations)
			if len(missingAnnotations) > 0 {
				return SecretManagedMetadataMismatch, fmt.Sprintf("Secret is missing these Managed Annotations: %v", sets.List(missingAnnotations)), true
			}

			extraAnnotations := managedAnnotations.Difference(expAnnotations)
			return SecretManagedMetadataMismatch, fmt.Sprintf("Secret has these extra Annotations: %v", sets.List(extraAnnotations)), true
		}

		return "", "", false
	}
}

// SecretSecretTemplateManagedFieldsMismatch will inspect the given Secret's
// managed fields for its Annotations and Labels, and compare this against the
// SecretTemplate on the given Certificate. Returns false if Annotations and
// Labels match on both the Certificate's SecretTemplate and the Secret's
// managed fields, true otherwise.
// Also returns true if the managed fields or signed certificate were not able
// to be decoded.
func SecretSecretTemplateManagedFieldsMismatch(fieldManager string) Func {
	return func(input Input) (string, string, bool) {
		managedLabels, managedAnnotations, err := secretLabelsAndAnnotationsManagedFields(input.Secret, fieldManager)
		if err != nil {
			return ManagedFieldsParseError, fmt.Sprintf("failed to decode managed fields on Secret: %s", err), true
		}

		// Remove the cert-manager annotations from the managed Annotations so we can compare
		// 1 to 1 against the SecretTemplate.
		for k := range managedAnnotations {
			if !strings.HasPrefix(k, "cert-manager.io/") &&
				!strings.HasPrefix(k, "controller.cert-manager.io/") {
				continue
			}

			delete(managedAnnotations, k)
		}

		// Remove the cert-manager labels from the managed Labels so we can
		// compare 1 to 1 against the SecretTemplate
		for k := range managedLabels {
			if !strings.HasPrefix(k, "cert-manager.io/") &&
				!strings.HasPrefix(k, "controller.cert-manager.io/") {
				continue
			}

			delete(managedLabels, k)
		}

		expLabels := sets.New[string]()
		expAnnotations := sets.New[string]()
		if input.Certificate.Spec.SecretTemplate != nil {
			for k := range input.Certificate.Spec.SecretTemplate.Labels {
				expLabels.Insert(k)
			}
			for k := range input.Certificate.Spec.SecretTemplate.Annotations {
				expAnnotations.Insert(k)
			}
		}

		if !managedLabels.Equal(expLabels) {
			missingLabels := expLabels.Difference(managedLabels)
			if len(missingLabels) > 0 {
				return SecretTemplateMismatch, fmt.Sprintf("Secret is missing these Template Labels: %v", sets.List(missingLabels)), true
			}

			extraLabels := managedLabels.Difference(expLabels)
			return SecretTemplateMismatch, fmt.Sprintf("Secret has these extra Labels: %v", sets.List(extraLabels)), true
		}

		if !managedAnnotations.Equal(expAnnotations) {
			missingAnnotations := expAnnotations.Difference(managedAnnotations)
			if len(missingAnnotations) > 0 {
				return SecretTemplateMismatch, fmt.Sprintf("Secret is missing these Template Annotations: %v", sets.List(missingAnnotations)), true
			}

			extraAnnotations := managedAnnotations.Difference(expAnnotations)
			return SecretTemplateMismatch, fmt.Sprintf("Secret has these extra Annotations: %v", sets.List(extraAnnotations)), true
		}

		return "", "", false
	}
}

// NOTE: The presence of the controller.cert-manager.io/fao label is checked
// by the SecretManagedLabelsAndAnnotationsManagedFieldsMismatch function.
func SecretBaseLabelsMismatch(input Input) (string, string, bool) {
	// check if Secret has the base labels. Currently there is only one base label
	if input.Secret.Labels == nil {
		return "", "", false
	}

	value, ok := input.Secret.Labels[cmapi.PartOfCertManagerControllerLabelKey]
	if !ok || value == "true" {
		return "", "", false
	}

	return SecretManagedMetadataMismatch, fmt.Sprintf("wrong base label %s value %q, expected \"true\"", cmapi.PartOfCertManagerControllerLabelKey, value), true
}

// SecretCertificateDetailsAnnotationsMismatch returns a validation violation when
// annotations on the Secret do not match the details of the x509 certificate that
// is stored in the Secret. This function will only compare the annotations that
// already exist on the Secret and are also present in the certificate metadata.
// NOTE: Missing and extra annotations are detected by the SecretManagedLabelsAndAnnotationsManagedFieldsMismatch
// function instead.
func SecretCertificateDetailsAnnotationsMismatch(input Input) (string, string, bool) {
	dataAnnotations, err := certificateDataAnnotationsForSecret(input.Secret)
	if err != nil {
		return InvalidCertificate, fmt.Sprintf("Failed getting secret annotations: %v", err), true
	}

	if match, key := mapsHaveMatchingValues(dataAnnotations, input.Secret.Annotations); !match {
		return SecretTemplateMismatch, fmt.Sprintf("Secret metadata %s does not match certificate metadata %s", input.Secret.Annotations[key], dataAnnotations[key]), true
	}

	return "", "", false
}

// SecretAdditionalOutputFormatsMismatch validates that the Secret has the
// expected Certificate AdditionalOutputFormats.
// Returns true (violation) if AdditionalOutputFormat(s) are present and any of
// the following:
//   - Secret key is missing
//   - Secret value is incorrect
func SecretAdditionalOutputFormatsMismatch(input Input) (string, string, bool) {
	const message = "Certificate's AdditionalOutputFormats doesn't match Secret Data"
	for _, format := range input.Certificate.Spec.AdditionalOutputFormats {
		switch format.Type {
		case cmapi.CertificateOutputFormatCombinedPEM:
			v, ok := input.Secret.Data[cmapi.CertificateOutputFormatCombinedPEMKey]
			if !ok || !bytes.Equal(v, internalcertificates.OutputFormatCombinedPEM(
				input.Secret.Data[corev1.TLSPrivateKeyKey],
				input.Secret.Data[corev1.TLSCertKey],
			)) {
				return AdditionalOutputFormatsMismatch, message, true
			}

		case cmapi.CertificateOutputFormatDER:
			v, ok := input.Secret.Data[cmapi.CertificateOutputFormatDERKey]
			if !ok || !bytes.Equal(v, internalcertificates.OutputFormatDER(input.Secret.Data[corev1.TLSPrivateKeyKey])) {
				return AdditionalOutputFormatsMismatch, message, true
			}
		}
	}

	return "", "", false
}

// SecretAdditionalOutputFormatsManagedFieldsMismatch validates that the field manager
// owns the correct Certificate's AdditionalOutputFormats in the Secret.
// Returns true (violation) if:
//   - missing AdditionalOutputFormat key owned by the field manager
//   - AdditionalOutputFormat key owned by the field manager shouldn't exist
//
// A violation with the reason `ManagedFieldsParseError` should be considered a
// non re-triable error.
func SecretAdditionalOutputFormatsManagedFieldsMismatch(fieldManager string) Func {
	const message = "Certificate's AdditionalOutputFormats doesn't match Secret ManagedFields"
	return func(input Input) (string, string, bool) {
		var (
			crtHasCombinedPEM, crtHasDER       bool
			secretHasCombinedPEM, secretHasDER bool
		)

		// Gather which additional output formats have been defined on the
		// Certificate.
		for _, format := range input.Certificate.Spec.AdditionalOutputFormats {
			switch format.Type {
			case cmapi.CertificateOutputFormatCombinedPEM:
				crtHasCombinedPEM = true
			case cmapi.CertificateOutputFormatDER:
				crtHasDER = true
			}
		}

		// Determine whether an output format key exists on the Secret which is
		// owned my the field manager.
		for _, managedField := range input.Secret.ManagedFields {
			if managedField.Manager != fieldManager || managedField.FieldsV1 == nil {
				continue
			}

			var fieldset fieldpath.Set
			if err := fieldset.FromJSON(bytes.NewReader(managedField.FieldsV1.Raw)); err != nil {
				return ManagedFieldsParseError, fmt.Sprintf("failed to decode managed fields on Secret: %s", err), true
			}

			if fieldset.Has(fieldpath.Path{
				{FieldName: ptr.To("data")},
				{FieldName: ptr.To(cmapi.CertificateOutputFormatCombinedPEMKey)},
			}) {
				secretHasCombinedPEM = true
			}

			if fieldset.Has(fieldpath.Path{
				{FieldName: ptr.To("data")},
				{FieldName: ptr.To(cmapi.CertificateOutputFormatDERKey)},
			}) {
				secretHasDER = true
			}
		}

		// Format present or missing on the Certificate should be reflected on the
		// Secret.
		if crtHasCombinedPEM != secretHasCombinedPEM || crtHasDER != secretHasDER {
			return AdditionalOutputFormatsMismatch, message, true
		}

		return "", "", false
	}
}

// SecretOwnerReferenceManagedFieldMismatch validates that the Secret has an
// owner reference to the Certificate if enabled. Returns true (violation) if:
// * the Secret doesn't have an owner reference and is expecting one
// * has an owner reference but is not expecting one
// A violation with the reason `ManagedFieldsParseError` should be considered a
// non re-triable error.
func SecretOwnerReferenceManagedFieldMismatch(ownerRefEnabled bool, fieldManager string) Func {
	return func(input Input) (string, string, bool) {
		var hasOwnerRefManagedField bool
		// Determine whether the Secret has the Certificate as an owner reference
		// which is owned by the field manager.
		for _, managedField := range input.Secret.ManagedFields {
			if managedField.Manager != fieldManager || managedField.FieldsV1 == nil {
				continue
			}

			var fieldset fieldpath.Set
			if err := fieldset.FromJSON(bytes.NewReader(managedField.FieldsV1.Raw)); err != nil {
				return ManagedFieldsParseError, fmt.Sprintf("failed to decode managed fields on Secret: %s", err), true
			}
			if fieldset.Has(fieldpath.Path{
				{FieldName: ptr.To("metadata")},
				{FieldName: ptr.To("ownerReferences")},
				{Key: &value.FieldList{{Name: "uid", Value: value.NewValueInterface(string(input.Certificate.UID))}}},
			}) {
				hasOwnerRefManagedField = true
				break
			}
		}

		// The presence of the Certificate owner reference should match owner
		// reference being enabled.
		if ownerRefEnabled != hasOwnerRefManagedField {
			return SecretOwnerRefMismatch,
				fmt.Sprintf("unexpected managed Secret Owner Reference field on Secret --enable-certificate-owner-ref=%t", ownerRefEnabled), true
		}

		return "", "", false
	}
}

// SecretOwnerReferenceMismatch validates that the Secret has the expected
// owner reference if it is enabled. Returns true (violation) if:
// * owner reference is enabled, but the reference has an incorrect value
func SecretOwnerReferenceMismatch(ownerRefEnabled bool) Func {
	return func(input Input) (string, string, bool) {
		// If the Owner Reference is not enabled, we don't need to check the value
		// and can exit early.
		if !ownerRefEnabled {
			return "", "", false
		}

		var (
			expRef                         = *metav1.NewControllerRef(input.Certificate, cmapi.SchemeGroupVersion.WithKind("Certificate"))
			hasOwnerRefMatchingCertificate bool
		)
		for _, ownerRef := range input.Secret.OwnerReferences {
			// Owner Reference slice is keyed by UID, so only one Owner Reference
			// with a particular UID can exist meaning we can break early.
			// https://github.com/kubernetes/apimachinery/blob/04356ed4cbb061c810a5e3d655802fd1e24284da/pkg/apis/meta/v1/types.go#L251
			if ownerRef.UID == input.Certificate.UID {
				if apiequality.Semantic.DeepEqual(ownerRef, expRef) {
					// Break early, there can only be one owner ref with this UID.
					hasOwnerRefMatchingCertificate = true
					break
				}
			}
		}

		// Owner reference is enabled at this point. If the Owner Reference value
		// doesn't match the expected value, return violation.
		if !hasOwnerRefMatchingCertificate {
			return SecretOwnerRefMismatch,
				fmt.Sprintf("unexpected Secret Owner Reference value on Secret --enable-certificate-owner-ref=%t", ownerRefEnabled), true
		}

		return "", "", false
	}
}

// mapsHaveMatchingValues returns true if the two maps have the same values for
// all common keys. Otherwise, the first key for which the values differ is returned.
// This function is stable and will always return the same key if the maps are
// the same.
func mapsHaveMatchingValues[Key cmp.Ordered, Value comparable](a, b map[Key]Value) (bool, Key) {
	keys := make([]Key, 0, len(a))
	for k := range a {
		if _, ok := b[k]; !ok {
			continue
		}

		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, k := range keys {
		if b[k] != a[k] {
			return false, k
		}
	}

	var zero Key
	return true, zero
}
