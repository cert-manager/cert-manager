/*
Copyright 2017 The Kubernetes Authors.

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

package certmanager

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Certificate is a type to represent a Certificate from ACME
type Certificate struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   CertificateSpec
	Status CertificateStatus
}

// CertificateSpec defines the desired state of Certificate
type CertificateSpec struct {
	Domains []string

	ProviderConfig
}

// ProviderConfig is a wrapping struct for the different types of supported
// providers configuration. In future, additional providers may be added here
// (eg. cfssl, AWS etc)
type ProviderConfig struct {
	ACME *ACME
}

// ACME contains the configuration for the ACME certificate provider
type ACME struct {
	Challenge ACMEChallengeType
	URL       string
	Email     string
	DNS       *ACMEDNSConfig
}

// ACMEChallengeType is the challenge type that should be used for ACME
// challenge verifications
type ACMEChallengeType string

var (
	// ACMEChallengeTypeHTTP01 is the ACME http-01 challenge type
	ACMEChallengeTypeHTTP01 ACMEChallengeType = "HTTP-01"
	// ACMEChallengeTypeDNS01 is the ACME dns-01 challenge type
	ACMEChallengeTypeDNS01 ACMEChallengeType = "DNS-01"
	// ACMEChallengeTypeTLSSNI01 is the ACME tls-sni-01 challenge type
	ACMEChallengeTypeTLSSNI01 ACMEChallengeType = "TLS-SNI-01"
)

// ACMEDNSConfig is a structure containing the ACME DNS configuration option.
// One and only one of the fields within it should be set, when the ACME
// challenge type is set to dns-01
type ACMEDNSConfig struct {
	CloudDNS *ACMEDNSConfigCloudDNS
}

// ACMEDNSConfigCloudDNS is a structure containing the DNS configuration for
// Google Cloud DNS
type ACMEDNSConfigCloudDNS struct{}

// CertificateStatus defines the observed state of Certificate
type CertificateStatus struct {
}
