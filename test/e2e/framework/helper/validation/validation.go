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
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/validation/certificates"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/validation/certificatesigningrequests"
)

func DefaultCertificateSet() []certificates.ValidationFunc {
	return []certificates.ValidationFunc{
		certificates.Expect2Or3KeysInSecret,
		certificates.ExpectCertificateDNSNamesToMatch,
		certificates.ExpectCertificateOrganizationToMatch,
		certificates.ExpectCertificateURIsToMatch,
		certificates.ExpectCorrectTrustChain,
		certificates.ExpectCARootCertificate,
		certificates.ExpectEmailsToMatch,
		certificates.ExpectValidAnnotations,
		certificates.ExpectValidCertificate,
		certificates.ExpectValidCommonName,
		certificates.ExpectValidNotAfterDate,
		certificates.ExpectValidPrivateKeyData,
		certificates.ExpectConditionReadyObservedGeneration,
		certificates.ExpectValidBasicConstraints,
	}
}

func DefaultCertificateSigningRequestSet() []certificatesigningrequests.ValidationFunc {
	return []certificatesigningrequests.ValidationFunc{
		certificatesigningrequests.ExpectValidCertificate,
		certificatesigningrequests.ExpectCertificateOrganizationToMatch,
		certificatesigningrequests.ExpectValidPrivateKeyData,
		certificatesigningrequests.ExpectCertificateDNSNamesToMatch,
		certificatesigningrequests.ExpectCertificateURIsToMatch,
		certificatesigningrequests.ExpectCertificateIPsToMatch,
		certificatesigningrequests.ExpectValidCommonName,
		certificatesigningrequests.ExpectKeyUsageUsageDigitalSignature,
		certificatesigningrequests.ExpectEmailsToMatch,
		certificatesigningrequests.ExpectIsCA,
		certificatesigningrequests.ExpectConditionApproved,
		certificatesigningrequests.ExpectConditiotNotDenied,
		certificatesigningrequests.ExpectConditionNotFailed,
	}
}

func CertificateSetForUnsupportedFeatureSet(fs featureset.FeatureSet) []certificates.ValidationFunc {
	// basics
	out := []certificates.ValidationFunc{
		certificates.Expect2Or3KeysInSecret,
		certificates.ExpectCertificateDNSNamesToMatch,
		certificates.ExpectCertificateOrganizationToMatch,
		certificates.ExpectValidAnnotations,
		certificates.ExpectValidCertificate,
		certificates.ExpectValidCommonName,
		certificates.ExpectValidNotAfterDate,
		certificates.ExpectValidPrivateKeyData,
		certificates.ExpectConditionReadyObservedGeneration,
		certificates.ExpectValidBasicConstraints,
	}

	if !fs.Contains(featureset.URISANsFeature) {
		out = append(out, certificates.ExpectCertificateURIsToMatch)
	}

	if !fs.Contains(featureset.EmailSANsFeature) {
		out = append(out, certificates.ExpectEmailsToMatch)
	}

	if !fs.Contains(featureset.SaveCAToSecret) {
		out = append(out, certificates.ExpectCorrectTrustChain)

		if !fs.Contains(featureset.SaveRootCAToSecret) {
			out = append(out, certificates.ExpectCARootCertificate)
		}
	}

	return out
}

func CertificateSigningRequestSetForUnsupportedFeatureSet(fs featureset.FeatureSet) []certificatesigningrequests.ValidationFunc {
	validations := DefaultCertificateSigningRequestSet()

	if !fs.Contains(featureset.DurationFeature) {
		validations = append(validations, certificatesigningrequests.ExpectValidDuration)
	}

	return validations
}
