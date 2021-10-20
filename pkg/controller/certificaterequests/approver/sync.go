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

package approver

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	ApprovedMessage = "Certificate request has been approved by cert-manager.io"
)

// Sync will set the "Approved" condition to True on synced
// CertificateRequests. If the "Denied", "Approved" or "Ready" condition
// already exists, exit early.
func (c *Controller) Sync(ctx context.Context, cr *cmapi.CertificateRequest) (err error) {
	log := logf.FromContext(ctx, "approver")

	switch {
	case
		// If the CertificateRequest has already been approved, exit early.
		apiutil.CertificateRequestIsApproved(cr),

		// If the CertificateRequest has already been denied, exit early.
		apiutil.CertificateRequestIsDenied(cr),

		// If the CertificateRequest is "Issued" or "Failed", exit early.
		apiutil.CertificateRequestReadyReason(cr) == cmapi.CertificateRequestReasonFailed,
		apiutil.CertificateRequestReadyReason(cr) == cmapi.CertificateRequestReasonIssued:
		return nil
	}

	// Update the CertificateRequest approved condition to true.
	cr = cr.DeepCopy()
	apiutil.SetCertificateRequestCondition(cr,
		cmapi.CertificateRequestConditionApproved,
		cmmeta.ConditionTrue,
		"cert-manager.io",
		ApprovedMessage,
	)

	// Update CertificateRequest with
	_, err = c.cmClient.CertmanagerV1().CertificateRequests(cr.Namespace).UpdateStatus(ctx, cr, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	c.recorder.Event(cr, corev1.EventTypeNormal, "cert-manager.io", ApprovedMessage)

	log.V(logf.DebugLevel).Info("approved certificate request")

	return nil
}
