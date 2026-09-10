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
)

// IsIncompleteFailure reports whether req has failed without saying so: a
// failureTime and no Ready condition. No in-tree issuer produces that state; an
// external issuer writing the two in separate updates can stop between them.
// Denied and InvalidRequest are decisions of their own and keep their branches.
func IsIncompleteFailure(req *cmapi.CertificateRequest) bool {
	return req.Status.FailureTime != nil &&
		apiutil.GetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady) == nil &&
		!apiutil.CertificateRequestIsDenied(req) &&
		!apiutil.CertificateRequestHasInvalidRequest(req)
}

// IncompleteFailureIsFromPreviousIssuance reports whether an incomplete failure
// predates the issuance in progress. creationTimestamp is checked as well: it
// comes from the API server and failureTime from the issuer, so an issuer whose
// clock is behind stamps a request it has just created with a time before the
// transition, and recycling on that alone would never pace the retry.
func IncompleteFailureIsFromPreviousIssuance(req *cmapi.CertificateRequest, issuing *cmapi.CertificateCondition) bool {
	return issuing != nil && issuing.LastTransitionTime != nil &&
		req.Status.FailureTime.Before(issuing.LastTransitionTime) &&
		req.CreationTimestamp.Time.Before(issuing.LastTransitionTime.Time)
}
