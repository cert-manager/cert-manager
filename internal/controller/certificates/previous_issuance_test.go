/*
Copyright 2026 The cert-manager Authors.

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

package certificates

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestFailedRequestIsFromPreviousIssuance(t *testing.T) {
	transition := metav1.NewTime(time.Now())
	issuing := &cmapi.CertificateCondition{
		Type:               cmapi.CertificateConditionIssuing,
		Status:             cmmeta.ConditionTrue,
		LastTransitionTime: &transition,
	}
	failedReadyCond := func(lastTransition *metav1.Time) gen.CertificateRequestModifier {
		return gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:               cmapi.CertificateRequestConditionReady,
			Status:             cmmeta.ConditionFalse,
			Reason:             cmapi.CertificateRequestReasonFailed,
			LastTransitionTime: lastTransition,
		})
	}

	tests := map[string]struct {
		mods    []gen.CertificateRequestModifier
		issuing *cmapi.CertificateCondition
		want    bool
	}{
		// The pre-existing behaviour, unchanged: a failureTime before the
		// Issuing transition dates the failure to the previous issuance.
		"failureTime set, before the Issuing transition": {
			mods: []gen.CertificateRequestModifier{
				gen.SetCertificateRequestFailureTime(metav1.NewTime(transition.Add(-time.Hour))),
				failedReadyCond(nil),
			},
			issuing: issuing,
			want:    true,
		},
		"failureTime set, after the Issuing transition": {
			mods: []gen.CertificateRequestModifier{
				gen.SetCertificateRequestFailureTime(metav1.NewTime(transition.Add(time.Minute))),
				failedReadyCond(nil),
			},
			issuing: issuing,
			want:    false,
		},
		// #9327: a failed request with no failureTime. The Ready condition's
		// lastTransitionTime dates the failure instead.
		"no failureTime, Ready condition transitioned before the Issuing transition": {
			mods: []gen.CertificateRequestModifier{
				failedReadyCond(&metav1.Time{Time: transition.Add(-time.Hour)}),
				func(cr *cmapi.CertificateRequest) { cr.CreationTimestamp = metav1.NewTime(transition.Add(-2 * time.Hour)) },
			},
			issuing: issuing,
			want:    true,
		},
		"no failureTime, Ready condition transitioned after the Issuing transition": {
			mods: []gen.CertificateRequestModifier{
				failedReadyCond(&metav1.Time{Time: transition.Add(time.Minute)}),
				func(cr *cmapi.CertificateRequest) { cr.CreationTimestamp = metav1.NewTime(transition.Add(-2 * time.Hour)) },
			},
			issuing: issuing,
			want:    false,
		},
		// The fallback path must not fire for a request created during this
		// issuance, however far behind the issuer's clock is.
		"no failureTime, Ready condition transitioned before the Issuing transition, but request created after it": {
			mods: []gen.CertificateRequestModifier{
				failedReadyCond(&metav1.Time{Time: transition.Add(-time.Hour)}),
				func(cr *cmapi.CertificateRequest) { cr.CreationTimestamp = metav1.NewTime(transition.Add(time.Second)) },
			},
			issuing: issuing,
			want:    false,
		},
		"no failureTime and a Ready condition with no lastTransitionTime": {
			mods: []gen.CertificateRequestModifier{
				failedReadyCond(nil),
				func(cr *cmapi.CertificateRequest) { cr.CreationTimestamp = metav1.NewTime(transition.Add(-2 * time.Hour)) },
			},
			issuing: issuing,
			want:    false,
		},
		// Not a failed request at all.
		"Ready condition with a different reason": {
			mods: []gen.CertificateRequestModifier{
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type:               cmapi.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             cmapi.CertificateRequestReasonPending,
					LastTransitionTime: &metav1.Time{Time: transition.Add(-time.Hour)},
				}),
				gen.SetCertificateRequestFailureTime(metav1.NewTime(transition.Add(-time.Hour))),
			},
			issuing: issuing,
			want:    false,
		},
		"no Ready condition": {
			mods: []gen.CertificateRequestModifier{
				gen.SetCertificateRequestFailureTime(metav1.NewTime(transition.Add(-time.Hour))),
			},
			issuing: issuing,
			want:    false,
		},
		// Degenerate conditions.
		"no Issuing condition": {
			mods: []gen.CertificateRequestModifier{
				gen.SetCertificateRequestFailureTime(metav1.NewTime(transition.Add(-time.Hour))),
				failedReadyCond(nil),
			},
			issuing: nil,
			want:    false,
		},
		"an Issuing condition with no lastTransitionTime is no evidence": {
			mods: []gen.CertificateRequestModifier{
				gen.SetCertificateRequestFailureTime(metav1.NewTime(transition.Add(-time.Hour))),
				failedReadyCond(nil),
			},
			issuing: &cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue},
			want:    false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, FailedRequestIsFromPreviousIssuance(gen.CertificateRequest("test", test.mods...), test.issuing))
		})
	}
}
