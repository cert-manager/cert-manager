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

const (
	// DoesNotExist is a policy violation reason for a scenario where
	// Certificate's spec.secretName secret does not exist.
	DoesNotExist string = "DoesNotExist"
	// MissingData is a policy violation reason for a scenario where
	// Certificate's spec.secretName secret has missing data.
	MissingData string = "MissingData"
	// InvalidKeyPair is a policy violation reason for a scenario where public
	// key of certificate does not match private key.
	InvalidKeyPair string = "InvalidKeyPair"
	// InvalidCertificate is a policy violation whereby the signed certificate in
	// the Input Secret could not be parsed or decoded.
	InvalidCertificate string = "InvalidCertificate"
	// InvalidCertificateRequest is a policy violation whereby the CSR in
	// the Input CertificateRequest could not be parsed or decoded.
	InvalidCertificateRequest string = "InvalidCertificateRequest"

	// SecretMismatch is a policy violation reason for a scenario where Secret's
	// private key does not match spec.
	SecretMismatch string = "SecretMismatch"
	// IncorrectIssuer is a policy violation reason for a scenario where
	// Certificate has been issued by incorrect Issuer.
	IncorrectIssuer string = "IncorrectIssuer"
	// IncorrectCertificate is a policy violation reason for a scenario where
	// the Secret referred to by this Certificate's spec.secretName,
	// already has a `cert-manager.io/certificate-name` annotation
	// with the name of another Certificate.
	IncorrectCertificate string = "IncorrectCertificate"
	// RequestChanged is a policy violation reason for a scenario where
	// CertificateRequest not valid for Certificate's spec.
	RequestChanged string = "RequestChanged"
	// Renewing is a policy violation reason for a scenario where
	// Certificate's renewal time is now or in the past.
	Renewing string = "Renewing"
	// Expired is a policy violation reason for a scenario where Certificate has
	// expired.
	Expired string = "Expired"
	// SecretTemplateMisMatch is a policy violation whereby the Certificate's
	// SecretTemplate is not reflected on the target Secret, either by having
	// extra, missing, or wrong Annotations or Labels.
	SecretTemplateMismatch string = "SecretTemplateMismatch"
	// SecretManagedMetadataMismatch is a policy violation whereby the Secret is
	// missing labels that should have been added by cert-manager
	SecretManagedMetadataMismatch string = "SecretManagedMetadataMismatch"

	// AdditionalOutputFormatsMismatch is a policy violation whereby the
	// Certificate's AdditionalOutputFormats is not reflected on the target
	// Secret, either by having extra, missing, or wrong values.
	AdditionalOutputFormatsMismatch string = "AdditionalOutputFormatsMismatch"
	// ManagedFieldsParseError is a policy violation whereby cert-manager was
	// unable to decode the managed fields on a resource.
	ManagedFieldsParseError string = "ManagedFieldsParseError"
	// SecretOwnerRefMismatch is a policy violation whereby the Secret either has
	// a missing owner reference to the Certificate, or has an owner reference it
	// shouldn't have.
	SecretOwnerRefMismatch string = "SecretOwnerRefMismatch"
)
