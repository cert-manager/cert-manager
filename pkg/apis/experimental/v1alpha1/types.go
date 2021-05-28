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

// CertificateSigningRequest specific Annotations
const (
	// CertificateSigningRequestDurationAnnotationKey is the
	// annotation key used to request a particular duration
	// represented as a Go Duration.
	CertificateSigningRequestDurationAnnotationKey = "experimental.cert-manager.io/request-duration"

	// CertificateSigningRequestIsCAAnnotationKey is the annotation key used to
	// request whether the certificate should be marked as CA.
	CertificateSigningRequestIsCAAnnotationKey = "experimental.cert-manager.io/request-is-ca"

	// CertificateSigningRequestCAAnnotationKey is the annotation key which will
	// contain the base 64 encoded resulting CA certificate which signed the CSR.
	CertificateSigningRequestCAAnnotationKey = "experimental.cert-manager.io/ca"
)
