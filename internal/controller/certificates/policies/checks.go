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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/clock"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/structured-merge-diff/v4/fieldpath"
	"sigs.k8s.io/structured-merge-diff/v4/value"

	internalcertificates "github.com/cert-manager/cert-manager/internal/controller/certificates"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates"
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
	pkData := input.Secret.Data[corev1.TLSPrivateKeyKey]
	certData := input.Secret.Data[corev1.TLSCertKey]
	// TODO: replace this with a generic decoder that can handle different
	//  formats such as JKS, P12 etc (i.e. add proper support for keystores)
	_, err := tls.X509KeyPair(certData, pkData)
	if err != nil {
		return InvalidKeyPair, fmt.Sprintf("Issuing certificate as Secret contains an invalid key-pair: %v", err), true
	}
	return "", "", false
}

func SecretPrivateKeyMatchesSpec(input Input) (string, string, bool) {
	if input.Secret.Data == nil || len(input.Secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
		return SecretMismatch, "Existing issued Secret does not contain private key data", true
	}

	pkBytes := input.Secret.Data[corev1.TLSPrivateKeyKey]
	pk, err := pki.DecodePrivateKeyBytes(pkBytes)
	if err != nil {
		return SecretMismatch, fmt.Sprintf("Existing issued Secret contains invalid private key data: %v", err), true
	}

	violations, err := certificates.PrivateKeyMatchesSpec(pk, input.Certificate.Spec)
	if err != nil {
		return SecretMismatch, fmt.Sprintf("Failed to check private key is up to date: %v", err), true
	}
	if len(violations) > 0 {
		return SecretMismatch, fmt.Sprintf("Existing private key is not up to date for spec: %v", violations), true
	}
	return "", "", false
}

func SecretIssuerAnnotationsNotUpToDate(input Input) (string, string, bool) {
	name := input.Secret.Annotations[cmapi.IssuerNameAnnotationKey]
	kind := input.Secret.Annotations[cmapi.IssuerKindAnnotationKey]
	group := input.Secret.Annotations[cmapi.IssuerGroupAnnotationKey]
	if name != input.Certificate.Spec.IssuerRef.Name ||
		!issuerKindsEqual(kind, input.Certificate.Spec.IssuerRef.Kind) ||
		!issuerGroupsEqual(group, input.Certificate.Spec.IssuerRef.Group) {
		return IncorrectIssuer, fmt.Sprintf("Issuing certificate as Secret was previously issued by %s", formatIssuerRef(name, kind, group)), true
	}
	return "", "", false
}

func CurrentCertificateRequestNotValidForSpec(input Input) (string, string, bool) {
	if input.CurrentRevisionRequest == nil {
		// Fallback to comparing the Certificate spec with the issued certificate.
		// This case is encountered if the CertificateRequest that issued the current
		// Secret is not available (most likely due to it being deleted).
		// This comparison is a lot less robust than comparing against the CertificateRequest
		// as it has to tolerate/permit certain fields being overridden or ignored by the
		// signer/issuer implementation.
		return currentSecretValidForSpec(input)
	}

	violations, err := certificates.RequestMatchesSpec(input.CurrentRevisionRequest, input.Certificate.Spec)
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
	violations, err := certificates.SecretDataAltNamesMatchSpec(input.Secret, input.Certificate.Spec)
	if err != nil {
		// This case should never be reached as we already check the certificate data can
		// be parsed in an earlier policy check, but handle it anyway.
		// TODO: log a message
		return "", "", false
	}

	if len(violations) > 0 {
		return SecretMismatch, fmt.Sprintf("Existing issued Secret is not up to date for spec: %v", violations), true
	}

	return "", "", false
}

// CurrentCertificateNearingExpiry returns a policy function that can be used to
// check whether an X.509 cert currently issued for a Certificate should be
// renewed.
func CurrentCertificateNearingExpiry(c clock.Clock) Func {

	return func(input Input) (string, string, bool) {

		// Determine if the certificate is nearing expiry solely by looking at
		// the actual cert, if it exists. We assume that at this point we have
		// called policy functions that check that input.Secret and
		// input.Secret.Data exists (SecretDoesNotExist and SecretIsMissingData).
		x509cert, err := pki.DecodeX509CertificateBytes(input.Secret.Data[corev1.TLSCertKey])
		if err != nil {
			// This case should never happen as it should always be caught by the
			// secretPublicKeysMatch function beforehand, but handle it just in case.
			return InvalidCertificate, fmt.Sprintf("Failed to decode stored certificate: %v", err), true
		}

		notBefore := metav1.NewTime(x509cert.NotBefore)
		notAfter := metav1.NewTime(x509cert.NotAfter)
		crt := input.Certificate
		renewalTime := certificates.RenewalTime(notBefore.Time, notAfter.Time, crt.Spec.RenewBefore)

		renewIn := renewalTime.Time.Sub(c.Now())
		if renewIn > 0 {
			//renewal time is in future, no need to renew
			return "", "", false
		}

		return Renewing, fmt.Sprintf("Renewing certificate as renewal was scheduled at %s", input.Certificate.Status.RenewalTime), true
	}
}

// CurrentCertificateHasExpired is used exclusively to check if the current
// issued certificate has actually expired rather than just nearing expiry.
func CurrentCertificateHasExpired(c clock.Clock) Func {
	return func(input Input) (string, string, bool) {
		certData, ok := input.Secret.Data[corev1.TLSCertKey]
		if !ok {
			return MissingData, "Missing Certificate data", true
		}
		// TODO: replace this with a generic decoder that can handle different
		//  formats such as JKS, P12 etc (i.e. add proper support for keystores)
		cert, err := pki.DecodeX509CertificateBytes(certData)
		if err != nil {
			// This case should never happen as it should always be caught by the
			// secretPublicKeysMatch function beforehand, but handle it just in case.
			return InvalidCertificate, fmt.Sprintf("Failed to decode stored certificate: %v", err), true
		}

		if c.Now().After(cert.NotAfter) {
			return Expired, fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC1123)), true
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

// SecretTemplateMismatchesSecret will inspect the given Secret's Annotations
// and Labels, and compare these maps against those that appear on the given
// Certificate's SecretTemplate.
// Returns false if all the Certificate's SecretTemplate Annotations and Labels
// appear on the Secret, or put another way, the Certificate's SecretTemplate
// is a subset of that in the Secret's Annotations/Labels.
// Returns true otherwise.
func SecretTemplateMismatchesSecret(input Input) (string, string, bool) {
	if input.Certificate.Spec.SecretTemplate == nil {
		return "", "", false
	}

	for kSpec, vSpec := range input.Certificate.Spec.SecretTemplate.Annotations {
		if v, ok := input.Secret.Annotations[kSpec]; !ok || v != vSpec {
			return SecretTemplateMismatch, "Certificate's SecretTemplate Annotations missing or incorrect value on Secret", true
		}
	}

	for kSpec, vSpec := range input.Certificate.Spec.SecretTemplate.Labels {
		if v, ok := input.Secret.Labels[kSpec]; !ok || v != vSpec {
			return SecretTemplateMismatch, "Certificate's SecretTemplate Labels missing or incorrect value on Secret", true
		}
	}

	return "", "", false
}

// SecretTemplateMismatchesSecretManagedFields will inspect the given Secret's
// managed fields for its Annotations and Labels, and compare this against the
// SecretTemplate on the given Certificate. Returns false if Annotations and
// Labels match on both the Certificate's SecretTemplate and the Secret's
// managed fields, true otherwise.
// Also returns true if the managed fields or signed certificate were not able
// to be decoded.
func SecretTemplateMismatchesSecretManagedFields(fieldManager string) Func {
	return func(input Input) (string, string, bool) {
		// Only attempt to decode the signed certificate, if one is available.
		var x509cert *x509.Certificate
		if len(input.Secret.Data[corev1.TLSCertKey]) > 0 {
			var err error
			x509cert, err = pki.DecodeX509CertificateBytes(input.Secret.Data[corev1.TLSCertKey])
			if err != nil {
				// This case should never happen as it should always be caught by the
				// secretPublicKeysMatch function beforehand, but handle it just in case.
				return InvalidCertificate, fmt.Sprintf("Failed to decode stored certificate: %v", err), true
			}
		}

		baseAnnotations := internalcertificates.AnnotationsForCertificateSecret(input.Certificate, x509cert)

		managedLabels, managedAnnotations := sets.NewString(), sets.NewString()

		for _, managedField := range input.Secret.ManagedFields {
			// If the managed field isn't owned by the cert-manager controller, ignore.
			if managedField.Manager != fieldManager || managedField.FieldsV1 == nil {
				continue
			}

			// Decode the managed field.
			var fieldset fieldpath.Set
			if err := fieldset.FromJSON(bytes.NewReader(managedField.FieldsV1.Raw)); err != nil {
				return ManagedFieldsParseError, fmt.Sprintf("failed to decode managed fields on Secret: %s", err), true
			}

			// Extract the labels and annotations of the managed fields.
			metadata := fieldset.Children.Descend(fieldpath.PathElement{
				FieldName: pointer.String("metadata"),
			})
			labels := metadata.Children.Descend(fieldpath.PathElement{
				FieldName: pointer.String("labels"),
			})
			annotations := metadata.Children.Descend(fieldpath.PathElement{
				FieldName: pointer.String("annotations"),
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

		// Remove the base Annotations from the managed Annotations so we can compare
		// 1 to 1 against the SecretTemplate.
		for k := range baseAnnotations {
			managedAnnotations = managedAnnotations.Delete(k)
		}

		// Check early for Secret Template being nil, and whether managed
		// labels/annotations are not.
		if input.Certificate.Spec.SecretTemplate == nil {
			if len(managedLabels) > 0 || len(managedAnnotations) > 0 {
				return SecretTemplateMismatch, "SecretTemplate is nil, but Secret contains extra managed entries", true
			}
			// SecretTemplate is nil. Managed annotations and labels are also empty.
			// Return false.
			return "", "", false
		}

		// SecretTemplate is not nil. Do length checks.
		if len(input.Certificate.Spec.SecretTemplate.Labels) != len(managedLabels) ||
			len(input.Certificate.Spec.SecretTemplate.Annotations) != len(managedAnnotations) {
			return SecretTemplateMismatch, "Certificate's SecretTemplate doesn't match Secret", true
		}

		// Check equal unsorted for SecretTemplate keys, and the managed fields
		// equivalents.
		for _, smap := range []struct {
			specMap    map[string]string
			managedSet sets.String
		}{
			{specMap: input.Certificate.Spec.SecretTemplate.Labels, managedSet: managedLabels},
			{specMap: input.Certificate.Spec.SecretTemplate.Annotations, managedSet: managedAnnotations},
		} {

			specSet := sets.NewString()
			for kSpec := range smap.specMap {
				specSet.Insert(kSpec)
			}

			if !specSet.Equal(smap.managedSet) {
				return SecretTemplateMismatch, "Certificate's SecretTemplate doesn't match Secret", true
			}
		}

		return "", "", false
	}
}

// SecretAdditionalOutputFormatsDataMismatch validates that the Secret has the
// expected Certificate AdditionalOutputFormats.
// Returns true (violation) if AdditionalOutputFormat(s) are present and any of
// the following:
//   - Secret key is missing
//   - Secret value is incorrect
func SecretAdditionalOutputFormatsDataMismatch(input Input) (string, string, bool) {
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

// SecretAdditionalOutputFormatsOwnerMismatch validates that the field manager
// owns the correct Certificate's AdditionalOutputFormats in the Secret.
// Returns true (violation) if:
//   - missing AdditionalOutputFormat key owned by the field manager
//   - AdditionalOutputFormat key owned by the field manager shouldn't exist
//
// A violation with the reason `ManagedFieldsParseError` should be considered a
// non re-triable error.
func SecretAdditionalOutputFormatsOwnerMismatch(fieldManager string) Func {
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
				{FieldName: pointer.String("data")},
				{FieldName: pointer.String(cmapi.CertificateOutputFormatCombinedPEMKey)},
			}) {
				secretHasCombinedPEM = true
			}

			if fieldset.Has(fieldpath.Path{
				{FieldName: pointer.String("data")},
				{FieldName: pointer.String(cmapi.CertificateOutputFormatDERKey)},
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
				{FieldName: pointer.String("metadata")},
				{FieldName: pointer.String("ownerReferences")},
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

// SecretOwnerReferenceValueMismatch validates that the Secret has the expected
// owner reference if it is enabled. Returns true (violation) if:
// * owner reference is enabled, but the reference has an incorrect value
func SecretOwnerReferenceValueMismatch(ownerRefEnabled bool) Func {
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
