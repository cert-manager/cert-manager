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
// The failure is dated by status.failureTime. No in-tree issuer can leave that
// field unset on a failed request (Reporter.Failed writes it together with the
// Ready condition), but an external issuer can, so when it is unset the Ready
// condition's lastTransitionTime is used as the fallback.
//
// In the fallback case only, the request's creationTimestamp must also predate
// the Issuing condition's lastTransitionTime. creationTimestamp comes from the
// API server while lastTransitionTime comes from the issuer, so an issuer
// whose clock is behind can stamp a request it has just created with a
// transition time before the current issuance; recycling on that alone would
// delete and recreate the request on every sync with no failure ever counted
// to pace it.
func FailedRequestIsFromPreviousIssuance(req *cmapi.CertificateRequest, issuing *cmapi.CertificateCondition) bool {
	readyCond := apiutil.GetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady)
	if readyCond == nil || readyCond.Status != cmmeta.ConditionFalse || readyCond.Reason != cmapi.CertificateRequestReasonFailed {
		return false
	}
	if issuing == nil || issuing.LastTransitionTime == nil {
		return false
	}

	if req.Status.FailureTime != nil {
		return req.Status.FailureTime.Before(issuing.LastTransitionTime)
	}

	// A failed request with no failureTime: date the failure by the Ready
	// condition's lastTransitionTime instead.
	if readyCond.LastTransitionTime == nil {
		return false
	}
	return readyCond.LastTransitionTime.Time.Before(issuing.LastTransitionTime.Time) &&
		req.CreationTimestamp.Time.Before(issuing.LastTransitionTime.Time)
}
