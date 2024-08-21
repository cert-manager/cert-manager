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
	"crypto"
	"crypto/x509"
	"fmt"
	"maps"
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

// TODO: add some kind of caching to the helper functions to avoid re-parsing
// the same data multiple times in the same policy chain.
type helper struct{}

func (helper) PrivateKey(input Input) (crypto.Signer, *Violation[InvalidInputReason]) {
	pkBytes := input.Secret.Data[corev1.TLSPrivateKeyKey]
	pk, err := pki.DecodePrivateKeyBytes(pkBytes)
	if err != nil {
		return nil, NewInvalidInputViolation(InvalidPrivateKey, fmt.Sprintf("Secret contains invalid private key data: %v", err))
	}

	return pk, nil
}

func (helper) X509Certificate(input Input) (*x509.Certificate, *Violation[InvalidInputReason]) {
	certBytes := input.Secret.Data[corev1.TLSCertKey]
	x509Cert, err := pki.DecodeX509CertificateBytes(certBytes)
	if err != nil {
		return nil, NewInvalidInputViolation(InvalidCertificate, fmt.Sprintf("Secret contains an invalid certificate: %v", err))
	}

	return x509Cert, nil
}

func (helper) ManagedFields(input Input, fieldManager string) (fieldpath.Set, *Violation[InvalidInputReason]) {
	var fieldset fieldpath.Set

	for _, managedField := range input.Secret.ManagedFields {
		// If the managed field isn't owned by the cert-manager controller, ignore.
		if managedField.Manager != fieldManager || managedField.FieldsV1 == nil {
			continue
		}

		// Decode the managed field.
		var set fieldpath.Set
		if err := set.FromJSON(bytes.NewReader(managedField.FieldsV1.Raw)); err != nil {
			return fieldset, NewInvalidInputViolation(InvalidManagedFields, fmt.Sprintf("failed to decode managed fields of Secret: %v", err))
		}

		fieldset = *fieldset.Union(&set)
	}

	return fieldset, nil
}

func SecretDoesNotExist(input Input) *Violation[InvalidInputReason] {
	if input.Secret == nil {
		return NewInvalidInputViolation(DoesNotExist, "Secret does not exist")
	}
	return nil
}

func SecretIsMissingData(input Input) *Violation[InvalidInputReason] {
	if input.Secret.Data == nil {
		return NewInvalidInputViolation(MissingData, "Secret does not contain any data")
	}
	pkData := input.Secret.Data[corev1.TLSPrivateKeyKey]
	certData := input.Secret.Data[corev1.TLSCertKey]
	if len(pkData) == 0 {
		return NewInvalidInputViolation(MissingData, "Secret does not contain a private key")
	}
	if len(certData) == 0 {
		return NewInvalidInputViolation(MissingData, "Secret does not contain a certificate")
	}
	return nil
}

func SecretContainsInvalidData(input Input) *Violation[InvalidInputReason] {
	_, violation := helper{}.PrivateKey(input)
	if violation != nil {
		return violation
	}

	_, violation = helper{}.X509Certificate(input)
	if violation != nil {
		return violation
	}

	return nil
}

func SecretPublicPrivateKeysNotMatching(input Input) *Violation[InvalidInputReason] {
	pk, violation := helper{}.PrivateKey(input)
	if violation != nil {
		return violation
	}

	x509Cert, violation := helper{}.X509Certificate(input)
	if violation != nil {
		return violation
	}

	equal, err := pki.PublicKeysEqual(x509Cert.PublicKey, pk.Public())
	if err != nil {
		return NewInvalidInputViolation(InvalidCertificate, fmt.Sprintf("Secret contains an invalid certificate: %v", err))
	}
	if !equal {
		return NewInvalidInputViolation(InvalidKeyPair, "Secret contains a private key that does not match the certificate")
	}

	return nil
}

func SecretPrivateKeyMismatchesSpec(input Input) *Violation[MaybeReason[IssuanceReason]] {
	pk, violation := helper{}.PrivateKey(input)
	if violation != nil {
		return MaybeValidation[IssuanceReason](violation)
	}

	violations := pki.PrivateKeyMatchesSpec(pk, input.Certificate.Spec)
	if len(violations) > 0 {
		return NewIssuanceViolation(SecretMismatch, fmt.Sprintf("Secret contains a private key that is not up to date with Certificate spec: %v", violations))
	}
	return nil
}

// SecretKeystoreFormatMismatch - When the keystore is not defined, the keystore
// related fields are removed from the secret.
// When one or more key stores are defined,  the
// corresponding secrets are generated.
// If the private key rotation is set to "Never", the key store related values are re-encoded
// as per the certificate specification
func SecretKeystoreFormatMismatch(input Input) *Violation[MaybeReason[PostIssuanceReason]] {
	_, issuerProvidesCA := input.Secret.Data[cmmeta.TLSCAKey]

	if input.Certificate.Spec.Keystores == nil {
		if len(input.Secret.Data[cmapi.PKCS12SecretKey]) != 0 ||
			len(input.Secret.Data[cmapi.PKCS12TruststoreKey]) != 0 ||
			len(input.Secret.Data[cmapi.JKSSecretKey]) != 0 ||
			len(input.Secret.Data[cmapi.JKSTruststoreKey]) != 0 {
			return NewPostIssuanceViolation(SecretKeystoreMismatch, "Keystore is not defined")
		}
		return nil
	}

	if input.Certificate.Spec.Keystores.JKS != nil {
		if input.Certificate.Spec.Keystores.JKS.Create {
			if len(input.Secret.Data[cmapi.JKSSecretKey]) == 0 ||
				(len(input.Secret.Data[cmapi.JKSTruststoreKey]) == 0 && issuerProvidesCA) {
				return NewPostIssuanceViolation(SecretKeystoreMismatch, "JKS Keystore key does not contain data")
			}
		} else {
			if len(input.Secret.Data[cmapi.JKSSecretKey]) != 0 ||
				len(input.Secret.Data[cmapi.JKSTruststoreKey]) != 0 {
				return NewPostIssuanceViolation(SecretKeystoreMismatch, "JKS Keystore create disabled")
			}
		}
	} else {
		if len(input.Secret.Data[cmapi.JKSSecretKey]) != 0 ||
			len(input.Secret.Data[cmapi.JKSTruststoreKey]) != 0 {
			return NewPostIssuanceViolation(SecretKeystoreMismatch, "JKS Keystore not defined")
		}
	}

	if input.Certificate.Spec.Keystores.PKCS12 != nil {
		if input.Certificate.Spec.Keystores.PKCS12.Create {
			if len(input.Secret.Data[cmapi.PKCS12SecretKey]) == 0 ||
				(len(input.Secret.Data[cmapi.PKCS12TruststoreKey]) == 0 && issuerProvidesCA) {
				return NewPostIssuanceViolation(SecretKeystoreMismatch, "PKCS12 Keystore key does not contain data")
			}
		} else {
			if len(input.Secret.Data[cmapi.PKCS12SecretKey]) != 0 ||
				len(input.Secret.Data[cmapi.PKCS12TruststoreKey]) != 0 {
				return NewPostIssuanceViolation(SecretKeystoreMismatch, "PKCS12 Keystore create disabled")
			}
		}
	} else {
		if len(input.Secret.Data[cmapi.PKCS12SecretKey]) != 0 ||
			len(input.Secret.Data[cmapi.PKCS12TruststoreKey]) != 0 {
			return NewPostIssuanceViolation(SecretKeystoreMismatch, "PKCS12 Keystore not defined")
		}
	}

	return nil
}

// SecretIssuerAnnotationsMismatch - When the issuer annotations are defined,
// it must match the issuer ref.
func SecretIssuerAnnotationsMismatch(input Input) *Violation[MaybeReason[IssuanceReason]] {
	name, ok1 := input.Secret.Annotations[cmapi.IssuerNameAnnotationKey]
	kind, ok2 := input.Secret.Annotations[cmapi.IssuerKindAnnotationKey]
	group, ok3 := input.Secret.Annotations[cmapi.IssuerGroupAnnotationKey]
	if (ok1 || ok2 || ok3) && // only check if an annotation is present
		name != input.Certificate.Spec.IssuerRef.Name ||
		!issuerKindsEqual(kind, input.Certificate.Spec.IssuerRef.Kind) ||
		!issuerGroupsEqual(group, input.Certificate.Spec.IssuerRef.Group) {
		return NewIssuanceViolation(IncorrectIssuer, fmt.Sprintf("Secret was previously issued by %q", formatIssuerRef(name, kind, group)))
	}
	return nil
}

// SecretCertificateNameAnnotationsMismatch - When the CertificateName annotation is defined,
// it must match the name of the Certificate.
func SecretCertificateNameAnnotationsMismatch(input Input) *Violation[MaybeReason[IssuanceReason]] {
	name, ok := input.Secret.Annotations[cmapi.CertificateNameKey]
	if (ok) && // only check if an annotation is present
		name != input.Certificate.Name {
		return NewIssuanceViolation(IncorrectCertificate, fmt.Sprintf("Secret was issued for %q. If this message is not transient, you might have two conflicting Certificates pointing to the same secret.", name))
	}
	return nil
}

// SecretPublicKeyDiffersFromCurrentCertificateRequest checks that the current CertificateRequest
// contains a CSR that is signed by the key stored in the Secret. A failure is often caused by the
// Secret being changed outside of the control of cert-manager, causing the current CertificateRequest
// to no longer match what is stored in the Secret.
func SecretPublicKeyDiffersFromCurrentCertificateRequest(input Input) *Violation[InvalidInputReason] {
	if input.CurrentRevisionRequest == nil {
		return nil
	}

	pk, violation := helper{}.PrivateKey(input)
	if violation != nil {
		return violation
	}

	csr, err := pki.DecodeX509CertificateRequestBytes(input.CurrentRevisionRequest.Spec.Request)
	if err != nil {
		return NewInvalidInputViolation(InvalidCertificateRequest, fmt.Sprintf("the current CertificateRequest failed to decode: %v", err))
	}

	equal, err := pki.PublicKeysEqual(csr.PublicKey, pk.Public())
	if err != nil {
		return NewInvalidInputViolation(InvalidCertificateRequest, fmt.Sprintf("the public key of the CertificateRequest is invalid: %v", err))
	}
	if !equal {
		return NewInvalidInputViolation(InvalidCertificateRequest, "Secret contains a private key that does not match the current CertificateRequest")
	}

	return nil
}

func CurrentCertificateRequestMismatchesSpec(input Input) *Violation[MaybeReason[IssuanceReason]] {
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
		return nil
	}
	if len(violations) > 0 {
		return NewIssuanceViolation(RequestChanged, fmt.Sprintf("fields on existing CertificateRequest resource are not up to date: %v", violations))
	}

	return nil
}

// currentSecretValidForSpec is not actually registered as part of the policy chain
// and is instead called by currentCertificateRequestValidForSpec if no there
// is no existing CertificateRequest resource.
func currentSecretValidForSpec(input Input) *Violation[MaybeReason[IssuanceReason]] {
	x509Cert, violation := helper{}.X509Certificate(input)
	if violation != nil {
		return MaybeValidation[IssuanceReason](violation)
	}

	// nolint: staticcheck // FuzzyX509AltNamesMatchSpec is used here for backwards compatibility
	violations := pki.FuzzyX509AltNamesMatchSpec(x509Cert, input.Certificate.Spec)
	if len(violations) > 0 {
		return NewIssuanceViolation(SecretMismatch, fmt.Sprintf("existing issued Secret is not up to date for spec: %v", violations))
	}

	return nil
}

// CurrentCertificateNearingExpiry returns a policy function that can be used to
// check whether an X.509 cert currently issued for a Certificate should be
// renewed.
func CurrentCertificateNearingExpiry(c clock.Clock) Policy[*Violation[MaybeReason[IssuanceReason]]] {
	return func(input Input) *Violation[MaybeReason[IssuanceReason]] {
		x509Cert, violation := helper{}.X509Certificate(input)
		if violation != nil {
			return MaybeValidation[IssuanceReason](violation)
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
			// renewal time is in future, no need to renew
			return nil
		}

		return NewIssuanceViolation(Renewing, fmt.Sprintf("renewal was scheduled at %s", input.Certificate.Status.RenewalTime))
	}
}

// CurrentCertificateHasExpired is used exclusively to check if the current
// issued certificate has actually expired rather than just nearing expiry.
func CurrentCertificateHasExpired(c clock.Clock) Policy[*Violation[MaybeReason[IssuanceReason]]] {
	return func(input Input) *Violation[MaybeReason[IssuanceReason]] {
		x509Cert, violation := helper{}.X509Certificate(input)
		if violation != nil {
			return MaybeValidation[IssuanceReason](violation)
		}

		if c.Now().After(x509Cert.NotAfter) {
			return NewIssuanceViolation(Expired, fmt.Sprintf("certificate expired on %s", x509Cert.NotAfter.Format(time.RFC1123)))
		}
		return nil
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
func SecretSecretTemplateMismatch(input Input) *Violation[MaybeReason[PostIssuanceReason]] {
	if input.Certificate.Spec.SecretTemplate == nil {
		return nil
	}

	if match, key := mapsHaveMatchingValues(input.Certificate.Spec.SecretTemplate.Annotations, input.Secret.Annotations); !match {
		return NewPostIssuanceViolation(SecretMetadataMismatch, fmt.Sprintf("Secret annotation %q has value %q, expected %q", key, input.Secret.Annotations[key], input.Certificate.Spec.SecretTemplate.Annotations[key]))
	}

	if match, key := mapsHaveMatchingValues(input.Certificate.Spec.SecretTemplate.Labels, input.Secret.Labels); !match {
		return NewPostIssuanceViolation(SecretMetadataMismatch, fmt.Sprintf("Secret label %q has value %q, expected %q", key, input.Secret.Labels[key], input.Certificate.Spec.SecretTemplate.Labels[key]))
	}

	return nil
}

// SecretLabelsAndAnnotationsManagedFieldsMismatch will inspect the given Secret's
// managed fields for its Annotations and Labels, and compare this against the expected
// Labels and Annotations which are a combination of the Certificate's SecretTemplate
// and the Annotations and Labels that are managed by cert-manager.
func SecretLabelsAndAnnotationsManagedFieldsMismatch(fieldManager string) Policy[*Violation[MaybeReason[PostIssuanceReason]]] {
	return func(input Input) *Violation[MaybeReason[PostIssuanceReason]] {
		x509Cert, violation := helper{}.X509Certificate(input)
		if violation != nil {
			// Ignore invalid certificate errors, these will be caught by the Readiness chain.
			// Instead, set the x509Cert to nil so we can continue checking the Secret.
			x509Cert = nil
		}

		fieldset, violation := helper{}.ManagedFields(input, fieldManager)
		if violation != nil {
			return MaybeValidation[PostIssuanceReason](violation)
		}

		managedLabels, managedAnnotations := sets.New[string](), sets.New[string]()
		fieldset.
			WithPrefix(fieldpath.PathElement{FieldName: ptr.To("metadata")}).
			WithPrefix(fieldpath.PathElement{FieldName: ptr.To("labels")}).
			Iterate(func(path fieldpath.Path) {
				managedLabels.Insert(strings.TrimPrefix(path.String(), "."))
			})
		fieldset.
			WithPrefix(fieldpath.PathElement{FieldName: ptr.To("metadata")}).
			WithPrefix(fieldpath.PathElement{FieldName: ptr.To("annotations")}).
			Iterate(func(path fieldpath.Path) {
				managedAnnotations.Insert(strings.TrimPrefix(path.String(), "."))
			})

		// Remove the annotations that can not be set on the Secret without re-issuing the certificate.
		managedAnnotations.Delete(cmapi.IssuerNameAnnotationKey)
		managedAnnotations.Delete(cmapi.IssuerKindAnnotationKey)
		managedAnnotations.Delete(cmapi.IssuerGroupAnnotationKey)
		managedAnnotations.Delete(cmapi.CertificateNameKey)

		expCertificateDataAnnotations, err := internalcertificates.AnnotationsForCertificate(x509Cert)
		if err != nil {
			return MaybeValidation[PostIssuanceReason](NewInvalidInputViolation(InvalidCertificate, fmt.Sprintf("failed computing secret annotations: %v", err)))
		}

		// Add the labels and annotations that are always managed by cert-manager to the expected set.
		expLabels := sets.New(
			cmapi.PartOfCertManagerControllerLabelKey, // SecretBaseLabelsMismatch checks the value
		)
		expAnnotations := sets.New(
			maps.Keys(expCertificateDataAnnotations)..., // SecretCertificateDetailsAnnotationsMismatch checks the value
		)

		// Add the labels and annotations that are set on the Certificate's SecretTemplate to the expected set.
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
				return NewPostIssuanceViolation(SecretMetadataMismatch, fmt.Sprintf("Secret is missing these labels: %v", sets.List(missingLabels)))
			}

			extraLabels := managedLabels.Difference(expLabels)
			return NewPostIssuanceViolation(SecretMetadataMismatch, fmt.Sprintf("Secret has these extra labels: %v", sets.List(extraLabels)))
		}

		if !managedAnnotations.Equal(expAnnotations) {
			missingAnnotations := expAnnotations.Difference(managedAnnotations)
			if len(missingAnnotations) > 0 {
				return NewPostIssuanceViolation(SecretMetadataMismatch, fmt.Sprintf("Secret is missing these annotations: %v", sets.List(missingAnnotations)))
			}

			extraAnnotations := managedAnnotations.Difference(expAnnotations)
			return NewPostIssuanceViolation(SecretMetadataMismatch, fmt.Sprintf("Secret has these extra annotations: %v", sets.List(extraAnnotations)))
		}

		return nil
	}
}

// NOTE: The presence of the controller.cert-manager.io/fao label is checked
// by the SecretManagedLabelsAndAnnotationsManagedFieldsMismatch function.
func SecretBaseLabelsMismatch(input Input) *Violation[MaybeReason[PostIssuanceReason]] {
	// check if Secret has the base labels. Currently there is only one base label
	if input.Secret.Labels == nil {
		return nil
	}

	value, ok := input.Secret.Labels[cmapi.PartOfCertManagerControllerLabelKey]
	if !ok || value == "true" {
		return nil
	}

	return NewPostIssuanceViolation(SecretMetadataMismatch, fmt.Sprintf("Secret label %q has value %q, expected \"true\"", cmapi.PartOfCertManagerControllerLabelKey, value))
}

// SecretCertificateDetailsAnnotationsMismatch returns a validation violation when
// annotations on the Secret do not match the details of the x509 certificate that
// is stored in the Secret. This function will only compare the annotations that
// already exist on the Secret and are also present in the certificate metadata.
// NOTE: Missing and extra annotations are detected by the SecretManagedLabelsAndAnnotationsManagedFieldsMismatch
// function instead.
func SecretCertificateDetailsAnnotationsMismatch(input Input) *Violation[MaybeReason[PostIssuanceReason]] {
	x509Cert, violation := helper{}.X509Certificate(input)
	if violation != nil {
		return MaybeValidation[PostIssuanceReason](violation)
	}

	dataAnnotations, err := internalcertificates.AnnotationsForCertificate(x509Cert)
	if err != nil {
		return MaybeValidation[PostIssuanceReason](NewInvalidInputViolation(InvalidCertificate, fmt.Sprintf("failed computing secret annotations: %v", err)))
	}

	if match, key := mapsHaveMatchingValues(dataAnnotations, input.Secret.Annotations); !match {
		return NewPostIssuanceViolation(SecretMetadataMismatch, fmt.Sprintf("Secret annotation %q has value %q, expected %q", key, input.Secret.Annotations[key], dataAnnotations[key]))
	}

	return nil
}

// SecretAdditionalOutputFormatsMismatch validates that the Secret has the
// expected Certificate AdditionalOutputFormats.
// Returns true (violation) if AdditionalOutputFormat(s) are present and the
// Secret value is incorrect
// NOTE: The presence of the correct AdditionalOutputFormats fields in the Secret
// is checked by the SecretAdditionalOutputFormatsManagedFieldsMismatch function.
func SecretAdditionalOutputFormatsMismatch(input Input) *Violation[MaybeReason[PostIssuanceReason]] {
	const message = "Certificate's AdditionalOutputFormats doesn't match Secret Data"
	for _, format := range input.Certificate.Spec.AdditionalOutputFormats {
		switch format.Type {
		case cmapi.CertificateOutputFormatCombinedPEM:
			v, ok := input.Secret.Data[cmapi.CertificateOutputFormatCombinedPEMKey]
			if ok && !bytes.Equal(v, internalcertificates.OutputFormatCombinedPEM(
				input.Secret.Data[corev1.TLSPrivateKeyKey],
				input.Secret.Data[corev1.TLSCertKey],
			)) {
				return NewPostIssuanceViolation(AdditionalOutputFormatsMismatch, message)
			}

		case cmapi.CertificateOutputFormatDER:
			v, ok := input.Secret.Data[cmapi.CertificateOutputFormatDERKey]
			if ok && !bytes.Equal(v, internalcertificates.OutputFormatDER(input.Secret.Data[corev1.TLSPrivateKeyKey])) {
				return NewPostIssuanceViolation(AdditionalOutputFormatsMismatch, message)
			}
		}
	}

	return nil
}

// SecretAdditionalOutputFormatsManagedFieldsMismatch validates that the field manager
// owns the correct Certificate's AdditionalOutputFormats in the Secret.
// Returns true (violation) if:
//   - missing AdditionalOutputFormat key owned by the field manager
//   - AdditionalOutputFormat key owned by the field manager shouldn't exist
//
// A violation with the reason `InvalidManagedFields` should be considered a
// non re-triable error.
func SecretAdditionalOutputFormatsManagedFieldsMismatch(fieldManager string) Policy[*Violation[MaybeReason[PostIssuanceReason]]] {
	return func(input Input) *Violation[MaybeReason[PostIssuanceReason]] {
		fieldset, violation := helper{}.ManagedFields(input, fieldManager)
		if violation != nil {
			return MaybeValidation[PostIssuanceReason](violation)
		}

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

		// Format present or missing on the Certificate should be reflected on the
		// Secret.
		if crtHasCombinedPEM != secretHasCombinedPEM || crtHasDER != secretHasDER {
			return NewPostIssuanceViolation(AdditionalOutputFormatsMismatch, "Certificate's AdditionalOutputFormats doesn't match Secret ManagedFields")
		}

		return nil
	}
}

// SecretOwnerReferenceManagedFieldMismatch validates that the Secret has an
// owner reference to the Certificate if enabled. Returns true (violation) if:
// * the Secret doesn't have an owner reference and is expecting one
// * has an owner reference but is not expecting one
// A violation with the reason `InvalidManagedFields` should be considered a
// non re-triable error.
func SecretOwnerReferenceManagedFieldMismatch(ownerRefEnabled bool, fieldManager string) Policy[*Violation[MaybeReason[PostIssuanceReason]]] {
	return func(input Input) *Violation[MaybeReason[PostIssuanceReason]] {
		fieldset, violation := helper{}.ManagedFields(input, fieldManager)
		if violation != nil {
			return MaybeValidation[PostIssuanceReason](violation)
		}

		var hasOwnerRefManagedField bool
		if fieldset.Has(fieldpath.Path{
			{FieldName: ptr.To("metadata")},
			{FieldName: ptr.To("ownerReferences")},
			{Key: &value.FieldList{{Name: "uid", Value: value.NewValueInterface(string(input.Certificate.UID))}}},
		}) {
			hasOwnerRefManagedField = true
		}

		// The presence of the Certificate owner reference should match owner
		// reference being enabled.
		if ownerRefEnabled != hasOwnerRefManagedField {
			return NewPostIssuanceViolation(SecretOwnerRefMismatch,
				fmt.Sprintf("unexpected managed Secret Owner Reference field on Secret --enable-certificate-owner-ref=%t", ownerRefEnabled))
		}

		return nil
	}
}

// SecretOwnerReferenceMismatch validates that the Secret has the expected
// owner reference if it is enabled. Returns true (violation) if:
// * owner reference is enabled, but the reference has an incorrect value
func SecretOwnerReferenceMismatch(ownerRefEnabled bool) Policy[*Violation[MaybeReason[PostIssuanceReason]]] {
	return func(input Input) *Violation[MaybeReason[PostIssuanceReason]] {
		// If the Owner Reference is not enabled, we don't need to check the value
		// and can exit early.
		if !ownerRefEnabled {
			return nil
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
			return NewPostIssuanceViolation(SecretOwnerRefMismatch, fmt.Sprintf("unexpected Secret Owner Reference value on Secret --enable-certificate-owner-ref=%t", ownerRefEnabled))
		}

		return nil
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
