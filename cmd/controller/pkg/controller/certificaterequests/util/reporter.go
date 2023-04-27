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

package util

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

const (
	readyMessage = "Certificate fetched from issuer successfully"
)

// A Reporter updates the Status of a CertificateRequest and sends an event
// to the Kubernetes Events API.
type Reporter struct {
	clock    clock.Clock
	recorder record.EventRecorder
}

// NewReporter returns a Reporter that will send events to the given EventRecorder.
func NewReporter(clock clock.Clock, recorder record.EventRecorder) *Reporter {
	return &Reporter{
		clock:    clock,
		recorder: recorder,
	}
}

// Failed marks a CertificateRequest as terminally failed and sends a corresponding event.
func (r *Reporter) Failed(cr *cmapi.CertificateRequest, err error, reason, message string) {
	// Set the FailureTime to c.clock.Now(), only if it has not been already set.
	if cr.Status.FailureTime == nil {
		nowTime := metav1.NewTime(r.clock.Now())
		cr.Status.FailureTime = &nowTime
	}

	message = fmt.Sprintf("%s: %v", message, err)
	r.recorder.Event(cr, corev1.EventTypeWarning, reason, message)
	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, message)

}

// Denied marks a CertificateRequest as terminally denied. No event is sent as it is
// expected to be sent by the approval controller.
func (r *Reporter) Denied(cr *cmapi.CertificateRequest) {
	// Set the FailureTime to c.clock.Now(), only if it has not been already set.
	if cr.Status.FailureTime == nil {
		nowTime := metav1.NewTime(r.clock.Now())
		cr.Status.FailureTime = &nowTime
	}

	message := "The CertificateRequest was denied by an approval controller"
	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, message)
}

// InvalidRequest marks a CertificateRequest as terminally Invalid. No event is sent as it
// is expected to be reported by the order controller.
func (r *Reporter) InvalidRequest(cr *cmapi.CertificateRequest, reason, message string) {
	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionInvalidRequest,
		cmmeta.ConditionTrue, reason, message)
}

// Pending marks a CertificateRequest as pending and sends a corresponding event.
//
// The event is only sent if the CertificateRequest is not already pending.
func (r *Reporter) Pending(cr *cmapi.CertificateRequest, err error, reason, message string) {
	if err != nil {
		message = fmt.Sprintf("%s: %v", message, err)
	}

	// If pending condition not already set then fire a Pending Event. This is to
	// reduce strain on the API server and avoid rate limiting ourselves for
	// Event creation.
	if apiutil.CertificateRequestReadyReason(cr) != cmapi.CertificateRequestReasonPending {
		r.recorder.Event(cr, corev1.EventTypeNormal, reason, message)
	}

	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, message)
}

// Ready marks a CertificateRequest as Ready and sends a corresponding event.
func (r *Reporter) Ready(cr *cmapi.CertificateRequest) {
	r.recorder.Event(cr, corev1.EventTypeNormal, "CertificateIssued", readyMessage)
	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady,
		cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, readyMessage)
}
