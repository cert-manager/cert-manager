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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// FailedRequestIsFromPreviousIssuance reports whether req is a failed
// CertificateRequest (Ready reason Failed) whose failure predates the
// Certificate's Issuing condition, i.e. a leftover from the previous
// issuance of the same revision.
//
// The failure is dated by the first of status.failureTime, the Ready
// condition's lastTransitionTime and the request's creationTimestamp:
// external issuers may set any subset of them. The middle one is a
// loose date: Pending and Failed both carry Status=False and
// apiutil.SetCertificateRequestCondition keeps the previous
// lastTransitionTime when the status is unchanged, so it usually
// holds the Pending stamp from just after creation rather than the
// failure itself. That is enough here, because it still falls on the
// right side of the Issuing transition. Whichever field is used,
// creationTimestamp must also predate the Issuing condition's
// lastTransitionTime. failureTime and lastTransitionTime are stamped
// by the issuer's clock while creationTimestamp comes from the API
// server, so an issuer whose clock is behind can stamp a request it
// has just created with a time before the current issuance.
func FailedRequestIsFromPreviousIssuance(req *cmapi.CertificateRequest, issuing *cmapi.CertificateCondition) bool {
	readyCond := apiutil.GetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady)
	if readyCond == nil || readyCond.Reason != cmapi.CertificateRequestReasonFailed {
		return false
	}
	if issuing == nil || issuing.LastTransitionTime == nil {
		return false
	}

	failedAt := req.Status.FailureTime
	if failedAt == nil {
		// External issuers may set the Ready condition without failureTime.
		failedAt = readyCond.LastTransitionTime
	}
	if failedAt == nil {
		// External issuers may set neither; creationTimestamp, which the
		// API server stamps on every object, is the only date left. A
		// request with no date at all is not evidence of a previous
		// issuance: the zero time would predate every transition.
		if req.CreationTimestamp.IsZero() {
			return false
		}
		failedAt = &metav1.Time{Time: req.CreationTimestamp.Time}
	}

	return failedAt.Before(issuing.LastTransitionTime) &&
		req.CreationTimestamp.Before(issuing.LastTransitionTime)
}
