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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// Clock is defined as a package var so it can be stubbed out during tests.
var Clock clock.Clock = clock.RealClock{}

func CertificateSigningRequestIsApproved(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, cond := range csr.Status.Conditions {
		if cond.Type == certificatesv1.CertificateApproved {
			return true
		}
	}
	return false
}

func CertificateSigningRequestIsDenied(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, cond := range csr.Status.Conditions {
		if cond.Type == certificatesv1.CertificateDenied {
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

func CertificateSigningRequestSetFailed(csr *certificatesv1.CertificateSigningRequest, reason, message string) {
	nowTime := metav1.NewTime(Clock.Now())

	// Since we only ever set this condition once (enforced by the API), we
	// needn't need to check whether the condition is already set.
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:               certificatesv1.CertificateFailed,
		Status:             corev1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: nowTime,
		LastUpdateTime:     nowTime,
	})

	logf.V(logf.InfoLevel).Infof("Setting lastTransitionTime for CertificateSigningRequest %s/%s condition Failed to %v",
		csr.Namespace, csr.Name, nowTime.Time)
}

func certificateSigningRequestGetCondition(csr *certificatesv1.CertificateSigningRequest, condType certificatesv1.RequestConditionType) *certificatesv1.CertificateSigningRequestCondition {
	for _, cond := range csr.Status.Conditions {
		if cond.Type == condType {
			return &cond
		}
	}
	return nil
}
