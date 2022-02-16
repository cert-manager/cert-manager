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
	"context"

	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certificatesapply "k8s.io/client-go/applyconfigurations/certificates/v1"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

// UpdateOrApplyStatus will update a CertificateSigningRequest's status, or
// Apply if the ServerSideApply feature gate is enabled.
// When the ServerSideApply feature is enabled; condType is optional, and will
// only be applied if non-empty and the condition with that type exists on the
// CertificateSigningRequest.
func UpdateOrApplyStatus(ctx context.Context,
	cl certificatesclient.CertificateSigningRequestInterface,
	csr *certificatesv1.CertificateSigningRequest,
	condType certificatesv1.RequestConditionType,
	fieldManager string,
) (*certificatesv1.CertificateSigningRequest, error) {
	if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
		status := certificatesapply.CertificateSigningRequestStatus().
			WithCertificate(csr.Status.Certificate...)

		if len(condType) > 0 {
			cond := certificateSigningRequestGetCondition(csr, condType)
			if cond != nil {
				status = status.WithConditions(
					&certificatesapply.CertificateSigningRequestConditionApplyConfiguration{
						Type: &cond.Type, Status: &cond.Status, Reason: &cond.Reason, Message: &cond.Message,
						LastTransitionTime: &cond.LastTransitionTime, LastUpdateTime: &cond.LastUpdateTime,
					},
				)
			}
		}

		return cl.ApplyStatus(ctx, certificatesapply.CertificateSigningRequest(csr.Name).WithStatus(status),
			metav1.ApplyOptions{Force: true, FieldManager: fieldManager},
		)
	} else {
		return cl.UpdateStatus(ctx, csr, metav1.UpdateOptions{})
	}
}
