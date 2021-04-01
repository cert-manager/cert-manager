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

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/controller/certificates"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/predicate"
)

// Gatherer is used to gather data about a Certificate in order to evaluate
// its current readiness/state by applying policy functions to it.
type Gatherer struct {
	CertificateRequestLister cmlisters.CertificateRequestLister
	SecretLister             corelisters.SecretLister
}

// DataForCertificate returns the secret as well as the "current" and "next"
// certificate request associated with the given certificate. It also returns
// the given certificate as-is.
//
// The "current" certificate request designates the certificate request that led
// to the current revision of the certificate. The "current" certificate request
// is by definition in a ready state, and can be seen as the source of
// information of the current certificate. The "current" certificate request is
// not to be confused with the "next" CR: the "next" CR is the not-yet-issued CR
// of the certificate. Its revision is the certificate's revision + 1. Most
// importantly, the "current" CR is by definition always ready. The "next", on
// the other side, is by definition (almost) never ready.
//
// We need the "current" certificate request because this CR contains the
// "source of truth" of the current certificate, and getting the "current" CR
// allows us to check whether the current certificate still matches the
// already-issued certificate request.
//
// An error is returned when two certificate requests are found for the pair
// (certificate's revision, certificate's uid). This function does not return
// any apierrors.NewNotFound errors for either the secret or the certificate
// request. Instead, if either the secret or the certificate request is not
// found, the returned secret (respectively, certificate request) is left nil.
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
