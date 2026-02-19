/*
Copyright 2021 The cert-manager Authors.

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

package validation

import (
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation/certificaterequests"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation/certificates"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/validation/certificatesigningrequests"
)

func CertificateSetForUnsupportedFeatureSet(fs featureset.FeatureSet) []certificates.ValidationFunc {
	// basics
	out := []certificates.ValidationFunc{
		certificates.ExpectCertificateDNSNamesToMatch,
		certificates.ExpectCertificateOrganizationToMatch,
		certificates.ExpectValidCertificate,
		certificates.ExpectValidPrivateKeyData,
		certificates.ExpectValidBasicConstraints,

		certificates.ExpectValidNotAfterDate,
		certificates.ExpectValidKeysInSecret,
		certificates.ExpectValidAnnotations,
		certificates.ExpectValidAdditionalOutputFormats,

		certificates.ExpectConditionReadyObservedGeneration,
	}

	if !fs.Has(featureset.SubjectKeyIdentifierFeature) {
		out = append(out, certificates.ExpectValidSubjectKeyIdentifier)
	}

	if !fs.Has(featureset.CommonNameFeature) {
		out = append(out, certificates.ExpectValidCommonName)
	}

	if !fs.Has(featureset.URISANsFeature) {
		out = append(out, certificates.ExpectCertificateURIsToMatch)
	}

	if !fs.Has(featureset.EmailSANsFeature) {
		out = append(out, certificates.ExpectEmailsToMatch)
	}

	if !fs.Has(featureset.IPAddressFeature) {
		out = append(out, certificates.ExpectCertificateIPsToMatch)
	}

	if !fs.Has(featureset.DurationFeature) {
		out = append(out, certificates.ExpectDurationToMatch)
	}

	if !fs.Has(featureset.SaveCAToSecret) {
		out = append(out, certificates.ExpectCorrectTrustChain)

		if !fs.Has(featureset.SaveRootCAToSecret) {
			out = append(out, certificates.ExpectCARootCertificate)
		}
	}

	return out
}

func CertificateRequestSetForUnsupportedFeatureSet(fs featureset.FeatureSet) []certificaterequests.ValidationFunc {
	// basics
	out := []certificaterequests.ValidationFunc{
		certificaterequests.ExpectCertificateDNSNamesToMatch,
		certificaterequests.ExpectCertificateOrganizationToMatch,
		certificaterequests.ExpectValidCertificate,
		certificaterequests.ExpectValidPrivateKeyData,
		certificaterequests.ExpectValidBasicConstraints,

		certificaterequests.ExpectConditionApproved,
		certificaterequests.ExpectConditionNotDenied,
	}

	if !fs.Has(featureset.CommonNameFeature) {
		out = append(out, certificaterequests.ExpectValidCommonName)
	}

	if !fs.Has(featureset.URISANsFeature) {
		out = append(out, certificaterequests.ExpectCertificateURIsToMatch)
	}

	if !fs.Has(featureset.EmailSANsFeature) {
		out = append(out, certificaterequests.ExpectEmailsToMatch)
	}

	if !fs.Has(featureset.IPAddressFeature) {
		out = append(out, certificaterequests.ExpectCertificateIPsToMatch)
	}

	if !fs.Has(featureset.DurationFeature) {
		out = append(out, certificaterequests.ExpectDurationToMatch)
	}

	return out
}

func CertificateSigningRequestSetForUnsupportedFeatureSet(fs featureset.FeatureSet) []certificatesigningrequests.ValidationFunc {
	// basics
	out := []certificatesigningrequests.ValidationFunc{
		certificatesigningrequests.ExpectCertificateDNSNamesToMatch,
		certificatesigningrequests.ExpectCertificateOrganizationToMatch,
		certificatesigningrequests.ExpectValidCertificate,
		certificatesigningrequests.ExpectValidPrivateKeyData,
		certificatesigningrequests.ExpectValidBasicConstraints,

		certificatesigningrequests.ExpectKeyUsageUsageDigitalSignature,

		certificatesigningrequests.ExpectConditionApproved,
		certificatesigningrequests.ExpectConditionNotDenied,
		certificatesigningrequests.ExpectConditionNotFailed,
	}

	if !fs.Has(featureset.CommonNameFeature) {
		out = append(out, certificatesigningrequests.ExpectValidCommonName)
	}

	if !fs.Has(featureset.URISANsFeature) {
		out = append(out, certificatesigningrequests.ExpectCertificateURIsToMatch)
	}

	if !fs.Has(featureset.EmailSANsFeature) {
		out = append(out, certificatesigningrequests.ExpectEmailsToMatch)
	}

	if !fs.Has(featureset.IPAddressFeature) {
		out = append(out, certificatesigningrequests.ExpectCertificateIPsToMatch)
	}

	if !fs.Has(featureset.DurationFeature) {
		out = append(out, certificatesigningrequests.ExpectDurationToMatch)
	}

	return out
}
