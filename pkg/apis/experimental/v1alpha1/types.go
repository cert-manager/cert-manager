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

package v1alpha1

import "time"

// CertificateSigningRequest specific Annotations
const (
	// CertificateSigningRequestDurationAnnotationKey is the
	// annotation key used to request a particular duration
	// represented as a Go Duration.
	CertificateSigningRequestDurationAnnotationKey = "experimental.cert-manager.io/request-duration"

	// CertificateSigningRequestIsCAAnnotationKey is the annotation key used to
	// request whether the certificate should be marked as CA.
	CertificateSigningRequestIsCAAnnotationKey = "experimental.cert-manager.io/request-is-ca"

	// CertificateSigningRequestMinimumDuration is the minimum allowed
	// duration that can be requested for a CertificateSigningRequest via
	// the experimental.cert-manager.io/request-duration annotation. This
	// has to be the same as the minimum allowed value for
	// spec.expirationSeconds of a CertificateSigningRequest
	CertificateSigningRequestMinimumDuration = time.Second * 600
)

// SelfSigned Issuer specific Annotations
const (
	// CertificateSigningRequestPrivateKeyAnnotationKey is the annotation key
	// used to reference a Secret resource containing the private key used to
	// sign the request.
	// This annotation *may* not be present, and is used by the 'self signing'
	// issuer type to self-sign certificates.
	CertificateSigningRequestPrivateKeyAnnotationKey = "experimental.cert-manager.io/private-key-secret-name"
)

// Venafi Issuer specific Annotations
const (
	// CertificateSigningRequestVenafiCustomFieldsAnnotationKey is the annotation
	// that passes on JSON encoded custom fields to the Venafi issuer.
	// This will only work with Venafi TPP v19.3 and higher.
	// The value is an array with objects containing the name and value keys for
	// example: `[{"name": "custom-field", "value": "custom-value"}]`
	CertificateSigningRequestVenafiCustomFieldsAnnotationKey = "venafi.experimental.cert-manager.io/custom-fields"

	// CertificateSigningRequestVenafiPickupIDAnnotationKey is the annotation key
	// used to record the Venafi Pickup ID of a certificate signing request that
	// has been submitted to the Venafi API for collection later.
	CertificateSigningRequestVenafiPickupIDAnnotationKey = "venafi.experimental.cert-manager.io/pickup-id"
)
