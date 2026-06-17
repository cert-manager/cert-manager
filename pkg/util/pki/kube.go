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

package pki

import (
	"crypto/x509"
	"fmt"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/cert-manager/cert-manager/pkg/apis/experimental/v1alpha1"
)

// DurationFromCertificateSigningRequest returns the duration that the user may
// have requested using the annotation
// "experimental.cert-manager.io/request-duration" or via the CSR
// spec.expirationSeconds field (the annotation is preferred since it predates
// the field which is only available in Kubernetes v1.22+).
// Returns the cert-manager default certificate duration when the user hasn't
// provided the annotation or spec.expirationSeconds.
func DurationFromCertificateSigningRequest(csr *certificatesv1.CertificateSigningRequest) (time.Duration, error) {
	requestedDuration, ok := csr.Annotations[experimentalapi.CertificateSigningRequestDurationAnnotationKey]
	if !ok {
		if csr.Spec.ExpirationSeconds != nil {
			return time.Duration(*csr.Spec.ExpirationSeconds) * time.Second, nil
		}

		// The user may not have set a duration annotation. Use the default
		// duration in this case.
		return cmapi.DefaultCertificateDuration, nil
	}

	duration, err := time.ParseDuration(requestedDuration)
	if err != nil {
		return -1, fmt.Errorf("failed to parse requested duration on annotation %q: %w",
			experimentalapi.CertificateSigningRequestDurationAnnotationKey, err)
	}

	return duration, nil
}

// BuildKeyUsagesKube returns a key usage and extended key usage of the x509 certificate
func BuildKeyUsagesKube(usages []certificatesv1.KeyUsage) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	var unk []certificatesv1.KeyUsage
	if len(usages) == 0 {
		usages = []certificatesv1.KeyUsage{certificatesv1.UsageDigitalSignature, certificatesv1.UsageKeyEncipherment}
	}

	var (
		ku  x509.KeyUsage
		eku []x509.ExtKeyUsage
	)

	for _, u := range usages {
		if kuse, ok := apiutil.KeyUsageTypeKube(u); ok {
			ku |= kuse
		} else if ekuse, ok := apiutil.ExtKeyUsageTypeKube(u); ok {
			eku = append(eku, ekuse)
		} else {
			unk = append(unk, u)
		}
	}

	if len(unk) > 0 {
		return -1, nil, fmt.Errorf("unknown key usages: %v", unk)
	}

	return ku, eku, nil
}
