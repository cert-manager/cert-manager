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

package util

import (
	certificatesv1 "k8s.io/api/certificates/v1"
)

func CertificateSigningRequestIsApproved(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, cond := range csr.Status.Conditions {
		if cond.Type == certificatesv1.CertificateApproved {
			return true
		}
	}
	return false
}

func CertificateSigningRequestIsFailed(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, cond := range csr.Status.Conditions {
		if cond.Type == certificatesv1.CertificateFailed {
			return true
		}
	}
	return false
}
