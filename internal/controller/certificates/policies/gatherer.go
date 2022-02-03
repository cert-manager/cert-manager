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

package policies

// In order to decide whether or not to reissue a certificate, we want to gather
// the "state of the world" regarding that particular certificate, which is the
// entire purpose of DataForCertificate. Along with the certificate's secret,
// DataForCertificate also returns two separate certificate requests: the
// "current" one and the "next" one.
//
// To understand the roles of the "current" and "next" certificate requests, let
// us look at three different scenarios: A, B and C.
//
// DIAGRAM (A1): in the first scenario, a user just created a cert-manager
// Kubernetes Certificate object. Since the object is new, only the "next"
// certificate request exists. You can see below that the first revision is "1":
//
//                    user creates
//                    certificate
//                         |              "current"+---------------------------------------------+
//                         |              +------->| No current CertificateRequest yet.          |
//                         v              |        +---------------------------------------------+
//               +---------------------+  |
//   CERTIFICATE | kind: Certificate   |  |        +---------------------------------------------+
//     NOT READY | status:             |  |        | kind: CertificateRequest                    |
//               |   revision: nil -------+        | metadata:                                   |
//               |   conditions:       |  |        |   annotations:                              |
//               |   - type: Issuing   |  |        |     cert-manager.io/certificate-revision: 1 |
//               |     status: True    |  +------->| status:                                     |
//               +---------------------+    "next" |   conditions:                               |
//                         |                       |    - type: Ready                            |
//                         |                       |      status: False                          |
//                         v                       |      reason: Pending                        |
//                        ...                      +---------------------------------------------+
//
// DIAGRAM (A2): the certificate in (A1) gets reconciled. Eventually, it becomes
// ready. Since the issuance is done, the "next" CR does not exist anymore:
//                        ...
//                         |
//                         v                       +---------------------------------------------+
//               +---------------------+           | kind: CertificateRequest                    |
//   CERTIFICATE | kind: Certificate   |           | metadata:                                   |
//         READY | status:             |  "current"|   annotations:                              |
//               |   revision: 1 ---------+------->|     cert-manager.io/certificate-revision: 1 |
//               |   conditions:       |  |        | status:                                     |
//               |    - type: Issuing  |  |        |   conditions:                               |
//               |      status: False  |  |        |    - type: Ready                            |
//               |      reason: Issued |  |        |      status: True                           |
//               |    - type: Ready    |  |        +---------------------------------------------+
//               |      status: True   |  |
//               +---------------------+  |
//                         |              |        +---------------------------------------------+
//                         v              +------> | No next CertificateRequest.                 |
//                  new certificate         "next" +---------------------------------------------+
//                   secret ready
//                    to be used
//
// Now that we've covered the base scenario A, let's dig into why we need the
// notion of the "current" certificate request. The second scenario B will help
// us understand the reason why DataForCertificate needs to be able to fetch the
// "current" certificate request.
//
// The "current" certificate request is important to us because the "current" CR
// contains the "source of truth" of the current certificate. The "current" CR
// allows us to check whether the current certificate still matches the
// already-issued certificate request.
//
// DIAGRAM (B1): the "current" certificate request can be pictured as the
// "current state of the world". When the certificate does not match its
// "current" certificate request, then certificate is in "mismatch" state and
// needs to be reissued.
//
//                                                  +-MISMATCH---------MISMATCH----------MISMATCH-+
//                     existing                     | kind: CertificateRequest                    |
//                      ready                       | metadata:                                   |
//                    certificate                   |   annotations:                              |
//                         |                        |     cert-manager.io/certificate-revision: 7 |
//                         |                        | status:                                     |
//                         |               "current"|   conditions:                               |
//                         v               +------->|    - type: Ready                            |
//                +--------------------+   |        |      status: True                           |
//    CERTIFICATE | kind: Certificate  |   |        +-MISMATCH---------MISMATCH----------MISMATCH-+
//       DOES NOT | status:            |   |
//      MATCH THE |   revision: 7 ---------+
//        CURRENT |   conditions:      |   |        +--------------------------------------------+
//    CERTIFICATE |     - type: Ready  |   |------->| No "next" CertificateRequest               |
//        REQUEST |       status: True |     "next" +--------------------------------------------+
//                +--------------------+
//                         |
//                         v
//                        ...
//
// DIAGRAM (B2): since the "current" CR does not match the certificate's spec,
// the trigger controller sets Issuing=True, and the "next" CR gets created:
//
//                        ...                       +-MISMATCH---------MISMATCH----------MISMATCH-+
//                         |                        | kind: CertificateRequest                    |
//                         |                        | metadata:                                   |
//                         |                        |   annotations:                              |
//                         |                        |     cert-manager.io/certificate-revision: 7 |
//                         |                        | status:                                     |
//                         v                        |   conditions:                               |
//                +---------------------+ "current" |    - type: Ready                            |
//   CERTIFICATE  | kind: Certificate   |  +------->|      status: True                           |
//      IS BEING  | status:             |  |        +-MISMATCH---------MISMATCH----------MISMATCH-+
//      REISSUED  |   revision: 7----------+
//                |   conditions:       |  |        +---------------------------------------------+
//                |    - type: Issuing  |  |        | kind: CertificateRequest                    |
//                |      status: True   |  |        | metadata:                                   |
//                |      reason: Pending|  |------->|   annotations:                              |
//                |    - type: Ready    |    "next" |     cert-manager.io/certificate-revision: 8 |
//                |      status: False  |           | status:                                     |
//                +---------------------+           |   conditions:                               |
//                                                  |    - type: Ready                            |
//                                                  |      status: False                          |
//                                                  |      reason: Pending                        |
//                                                  +---------------------------------------------+
//
//
// The third scenario C will help us understand the reason why
// DataForCertificate has a "next" certificate request.
//
// DIAGRAM (C1): imagine that a user creates a certificate that contains a
// mistake. The certificate will end up in failure state and will be retried
// after 1 hour:
//
//                  user creates a        "current" +---------------------------------------------+
//                 certificate with        +------->| No current CertificateRequest               |
//                 an invalid field        |        +---------------------------------------------+
//                         |               |
//                         |               |        +---------------------------------------------+
//                         v               |        | kind: CertificateRequest                    |
//               +---------------------+   |        | metadata:                                   |
//   CERTIFICATE | kind: Certificate   |   |        |   annotations:                              |
//    IS FAILING | status:             |   |        |     cert-manager.io/certificate-revision: 1 |
//               |   revision: nil --------+        | status:                                     |
//               |   conditions:       |   |        |   conditions:                               |
//               |    - type: Issuing  |   +------->|    - type: Failed                           |
//               |      status: False  |     "next" |      status: True                           |
//               |      reason: Failed |            +---------------------------------------------+
//               |   lastFailureTime: *|
//               +---------------------+
//                         |
//                         v
//                        ...
//
// DIAGRAM (C2): now, imagine that the user wants to fix their mistake and
// update the certificate with a correct value. Of course, the user does not
// want to wait for 1 hour for the automatic re-issue. By looking at the "next"
// CR, we can detect whether the "next" CR still matches the certificate. This
// behavior only occurs when the certificate is failing:
//                        ...
//                         |              "current" +---------------------------------------------+
//                         |               +------->| No current CertificateRequest               |
//                         |               |        +---------------------------------------------+
//                         v               |
//               +---------------------+   |
//   CERTIFICATE | kind: Certificate   |   |        +-MISMATCH---------MISMATCH----------MISMATCH-+
//     IS SET TO | status:             |   |        | kind: CertificateRequest                    |
//   "REISSUING" |   revision: nil --------+        | metadata:                                   |
//       DUE TO  |   conditions:       |   |        |   annotations:                              |
//     MISMATCH  |    - type: Issuing  |   |        |     cert-manager.io/certificate-revision: 1 |
//               |      status: True   |   |        | status:                                     |
//               |      reason: Pending|   |------->|   conditions:                               |
//               |    - type: Ready    |     "next" |    - type: Failed                           |
//               |      status: False  |            |      status: True                           |
//               +---------------------+            +-MISMATCH---------MISMATCH----------MISMATCH-+
//                         |
//                         v
//                        ...
//
// DIAGRAM (C3): the trigger controller is able to detect the mismatch: it
// triggers a re-issuance, and the failing certificate request is re-issued with
// the same revision number:
//                        ...
//                         |
//         user updates the|
//       invalid field with|
//            a valid value|               "current" +---------------------------------------------+
//                         |                +------->| No current CertificateRequest               |
//                         v                |        +---------------------------------------------+
//                +----------------------+  |
//       PREVIOUS | kind: Certificate    |  |
//    CERTIFICATE | status:              |  |        +-NEW---------------NEW-------------------NEW-+
//     REQUEST IS |   revision: nil --------+        | kind: CertificateRequest                    |
//       REPLACED |   conditions:        |  |        | metadata:                                   |
//                |    - type: Ready     |  |        |   annotations:                              |
//                |      status: False   |  |        |     cert-manager.io/certificate-revision: 1 |
//                |    - type: Issuing   |  |------->| status:                                     |
//                |      status: True    |    "next" |   conditions:                               |
//                |      reason: Pending |           |    - type: Ready                            |
//                +----------------------+           |      status: False                          |
//                                                   |      reason: Pending                        |
//                                                   +-NEW---------------NEW-------------------NEW-+

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/predicate"
)

// Gatherer is used to gather data about a Certificate in order to evaluate
// its current readiness/state by applying policy functions to it.
type Gatherer struct {
	CertificateRequestLister cmlisters.CertificateRequestLister
	SecretLister             corelisters.SecretLister
}

// DataForCertificate returns the secret as well as the "current" and "next"
// certificate request associated with the given certificate. It also returns
// the given certificate as-is. To know more about the "current" and "next"
// certificate requests and why we want to be fetching them along with the
// certificate's secret, take a look at the top comment on this file.
//
// DataForCertificate returns an error when duplicate CRs are found for the
// "current" or the "next" revision. DataForCertificate does not return any
// apierrors.NewNotFound; instead, if either of the objects (current CR, next CR
// or secret) is not found, then the returned value of this object is left nil.
func (g *Gatherer) DataForCertificate(ctx context.Context, crt *cmapi.Certificate) (Input, error) {
	log := logf.FromContext(ctx)
	// Attempt to fetch the Secret being managed but tolerate NotFound errors.
	secret, err := g.SecretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if err != nil && !apierrors.IsNotFound(err) {
		return Input{}, err
	}

	// Attempt to fetch the CertificateRequest for the current status.revision.
	//
	// We can skip looking for the current CR when the status.revision is nil
	// since there cannot be any available "current" certificate request if the
	// certificate's revision is empty. That is due to the fact that the
	// certificate's revision field stays nil until the first certificate
	// request (revision "1") has become ready.
	var curCR *cmapi.CertificateRequest
	if crt.Status.Revision != nil {
		// As depicted in the above diagram (A), there cannot be any "current"
		// certificate request revision when the certificate's revision is nil,
		// hence the above if revision != nil.

		reqs, err := certificates.ListCertificateRequestsMatchingPredicates(g.CertificateRequestLister.CertificateRequests(crt.Namespace),
			labels.Everything(),
			predicate.ResourceOwnedBy(crt),
			predicate.CertificateRequestRevision(*crt.Status.Revision),
		)
		if err != nil {
			return Input{}, err
		}
		switch {
		case len(reqs) > 1:
			return Input{}, fmt.Errorf("multiple CertificateRequests were found for the 'current' revision %v, issuance is skipped until there are no more duplicates", *crt.Status.Revision)
		case len(reqs) == 1:
			curCR = reqs[0]
		case len(reqs) == 0:
			log.V(logf.DebugLevel).Info("Found no CertificateRequest resources owned by this Certificate for the current revision", "revision", *crt.Status.Revision)
		}
	}

	// Attempt fetching the CertificateRequest for the next status.revision.
	var nextCR *cmapi.CertificateRequest
	nextCRRevision := 1
	if crt.Status.Revision != nil {
		// As depicted in the above diagram (A), the "next" certificate request
		// revision always starts at 1 when the certificate's status.revision is
		// nil.
		nextCRRevision = *crt.Status.Revision + 1
	}
	reqs, err := certificates.ListCertificateRequestsMatchingPredicates(g.CertificateRequestLister.CertificateRequests(crt.Namespace),
		labels.Everything(),
		predicate.ResourceOwnedBy(crt),
		predicate.CertificateRequestRevision(nextCRRevision),
	)
	if err != nil {
		return Input{}, err
	}
	switch {
	case len(reqs) > 1:
		// This error feels worthless: we know that the "duplicate certificate
		// requests" will be fixed almost instantaneously; showing this error to
		// the user is pointless since it won't even help in a debug session.
		// Unfortunately, we DO have to return an error just for the purpose of
		// making sure that the caller function (trigger controller, readiness
		// controller) will abort their sync and retrigger a new sync, with the
		// hope that the duplicate will have been removed before the next
		// resync.
		return Input{}, fmt.Errorf("multiple CertificateRequests were found for the 'next' revision %v, issuance is skipped until there are no more duplicates", nextCRRevision)
	case len(reqs) == 1:
		nextCR = reqs[0]
	case len(reqs) == 0:
		log.V(logf.DebugLevel).Info("Found no CertificateRequest resources owned by this Certificate for the next revision", "revision", nextCRRevision)
	}

	return Input{
		Certificate:            crt,
		Secret:                 secret,
		CurrentRevisionRequest: curCR,
		NextRevisionRequest:    nextCR,
	}, nil
}
