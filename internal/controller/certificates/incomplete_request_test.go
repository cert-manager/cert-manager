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

func TestIsIncompleteFailure(t *testing.T) {
	failureTime := metav1.NewTime(time.Now())
	condition := func(t cmapi.CertificateRequestConditionType) gen.CertificateRequestModifier {
		return gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{Type: t, Status: cmmeta.ConditionTrue})
	}

	tests := map[string]struct {
		mods []gen.CertificateRequestModifier
		want bool
	}{
		"a failureTime and no Ready condition": {
			mods: []gen.CertificateRequestModifier{gen.SetCertificateRequestFailureTime(failureTime)},
			want: true,
		},
		"no failureTime": {
			want: false,
		},
		"a Ready condition, whatever it says, is the existing branches' business": {
			mods: []gen.CertificateRequestModifier{gen.SetCertificateRequestFailureTime(failureTime), condition(cmapi.CertificateRequestConditionReady)},
			want: false,
		},
		"denied": {
			mods: []gen.CertificateRequestModifier{gen.SetCertificateRequestFailureTime(failureTime), condition(cmapi.CertificateRequestConditionDenied)},
			want: false,
		},
		"invalid": {
			mods: []gen.CertificateRequestModifier{gen.SetCertificateRequestFailureTime(failureTime), condition(cmapi.CertificateRequestConditionInvalidRequest)},
			want: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, IsIncompleteFailure(gen.CertificateRequest("test", test.mods...)))
		})
	}
}

func TestIncompleteFailureIsFromPreviousIssuance(t *testing.T) {
	transition := metav1.NewTime(time.Now())
	issuing := &cmapi.CertificateCondition{
		Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue, LastTransitionTime: &transition,
	}
	request := func(failure, creation time.Duration) *cmapi.CertificateRequest {
		return gen.CertificateRequest("test",
			gen.SetCertificateRequestFailureTime(metav1.NewTime(transition.Add(failure))),
			func(cr *cmapi.CertificateRequest) { cr.CreationTimestamp = metav1.NewTime(transition.Add(creation)) },
		)
	}

	tests := map[string]struct {
		req     *cmapi.CertificateRequest
		issuing *cmapi.CertificateCondition
		want    bool
	}{
		"both timestamps predate the transition": {
			req: request(-time.Hour, -2*time.Hour), issuing: issuing, want: true,
		},
		"failed during this issuance": {
			req: request(time.Minute, time.Second), issuing: issuing, want: false,
		},
		// An issuer whose clock is behind stamps a request it has just created
		// with a time before the transition.
		"created during this issuance but stamped with an older failureTime": {
			req: request(-time.Hour, 2*time.Second), issuing: issuing, want: false,
		},
		"no Issuing condition": {
			req: request(-time.Hour, -2*time.Hour), issuing: nil, want: false,
		},
		"an Issuing condition with no transition time is no evidence": {
			req:     request(-time.Hour, -2*time.Hour),
			issuing: &cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue},
			want:    false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, IncompleteFailureIsFromPreviousIssuance(test.req, test.issuing))
		})
	}
}
