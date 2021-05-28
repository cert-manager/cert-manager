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

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	experimentalapi "github.com/jetstack/cert-manager/pkg/apis/experimental/v1alpha1"
)

// GenerateTemplateFromCertificateSigningRequest will create an
// *x509.Certificate from the given CertificateSigningRequest resource
func GenerateTemplateFromCertificateSigningRequest(csr *certificatesv1.CertificateSigningRequest) (*x509.Certificate, error) {
	duration := cmapi.DefaultCertificateDuration
	requestedDuration, ok := csr.Annotations[experimentalapi.CertificateSigningRequestDurationAnnotationKey]
	if ok {
		dur, err := time.ParseDuration(requestedDuration)
		if err != nil {
			return nil, fmt.Errorf("failed to parse requested duration on annotation %q: %w",
				experimentalapi.CertificateSigningRequestDurationAnnotationKey, err)
		}
		duration = dur
	}

	ku, eku, err := BuildKeyUsagesKube(csr.Spec.Usages)
	if err != nil {
		return nil, err
	}

	isCA := csr.Annotations[experimentalapi.CertificateSigningRequestIsCAAnnotationKey] == "true"

	return GenerateTemplateFromCSRPEMWithUsages(csr.Spec.Request, duration, isCA, ku, eku)
}

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
