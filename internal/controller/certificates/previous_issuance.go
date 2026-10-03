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
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// FailedRequestIsFromPreviousIssuance reports whether req is a
// Ready=False/Failed CertificateRequest whose failure belongs to an issuance
// earlier than the one recorded by the Certificate's Issuing condition. Such a
// request is a leftover from the previous issuance of the same revision and
// must be replaced rather than re-counted.
//
// The failure is dated by the first of these fields the issuer left set:
//
//  1. status.failureTime, which Reporter.Failed stamps with the issuer's own
//     clock;
//  2. the Ready condition's lastTransitionTime. Note this dates when Ready
//     first became False rather than the failure itself:
//     apiutil.SetCertificateRequestCondition keeps the previous
//     lastTransitionTime when the status is unchanged, and Pending and Failed
//     both carry Status=False, so an issuer that went Pending then Failed has
//     a stamp from the Pending transition;
//  3. the request's creationTimestamp when an external issuer left both status
//     fields empty. Both fields are optional in the API, and without this
//     fallback such a request would be counted on every issuance and never
//     deleted. The API server always stamps creationTimestamp; an object
//     without one carries no date at all, and a missing date is not evidence
//     of an older issuance, so that case returns false below.
//
// Whichever field dates the failure, the request's creationTimestamp must also
// predate the Issuing condition's lastTransitionTime. The first two come from
// the issuer's clock while creationTimestamp comes from the API server, so an
// issuer whose clock is behind can stamp a request it has just created before
// the current issuance; recycling on that alone would delete and recreate the
// request on every sync with no failure ever counted to pace it. The cost of
// this guard is that a request created during an earlier issuance but failed
// during the current one is replaced without being counted; its replacement's
// failure is counted as normal.
func FailedRequestIsFromPreviousIssuance(req *cmapi.CertificateRequest, issuing *cmapi.CertificateCondition) bool {
	readyCond := apiutil.GetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady)
	if readyCond == nil || readyCond.Status != cmmeta.ConditionFalse || readyCond.Reason != cmapi.CertificateRequestReasonFailed {
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
		// External issuers may set neither. The API server stamps
		// creationTimestamp on every object; if it is absent too then this
		// request carries no date, and dating it to the zero time would
		// classify it as older than every issuance rather than unknown.
		if req.CreationTimestamp.IsZero() {
			return false
		}
		failedAt = &metav1.Time{Time: req.CreationTimestamp.Time}
	}

	return failedAt.Before(issuing.LastTransitionTime) &&
		req.CreationTimestamp.Before(issuing.LastTransitionTime)
}
