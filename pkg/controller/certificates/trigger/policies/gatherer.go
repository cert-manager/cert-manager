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

// DataForCertificate returns the secret as well as the "current"
// certificate request associated with the given certificate. It also
// returns the given certificate as-is.
//
// The "current" certificate request designates the certificate request
// that led to the current revision of the certificate. The "current"
// certificate request is by definition in a ready state, and can be seen
// as the source of information of the current certificate.
//
// This "current" certificate request is not to be confused with the "next"
// certificate request that you might get by listing the CRs for the
// certificate's revision+1; these "next" CRs might not be ready yet.
//
// We need the "current" certificate request because this CR contains the
// "source of truth" of the current certificate, and getting the "current"
// CR allows is to check whether the current certificate still matches the
// already-issued certificate request.
//
// An error is returned when two certificate requests are found for the
// couple (certificate's revision, certificate's uid). This function does
// not return any apierrors.NewNotFound errors for either the secret or the
// certificate request. Instead, if either the secret or the certificate
// request is not found, the returned secret (respectively, certificate
// request) is left nil.
func (g *Gatherer) DataForCertificate(ctx context.Context, crt *cmapi.Certificate) (Input, error) {
	log := logf.FromContext(ctx)
	// Attempt to fetch the Secret being managed but tolerate NotFound errors.
	secret, err := g.SecretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if err != nil && !apierrors.IsNotFound(err) {
		return Input{}, err
	}

	// There can't be any available "current" certificate request if the
	// certificate's revision has not been set yet. That is due to the fact
	// that the certificate's revision field stays nil until the first
	// certificate request (revision "1") has become ready.
	if crt.Status.Revision == nil {
		return Input{Secret: secret, Certificate: crt}, nil
	}

	// Attempt to fetch the CertificateRequest resource for the current 'status.revision'.
	var req *cmapi.CertificateRequest
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
			return Input{}, fmt.Errorf("multiple CertificateRequest resources exist for the current revision, not triggering new issuance until requests have been cleaned up")
		case len(reqs) == 1:
			req = reqs[0]
		case len(reqs) == 0:
			log.V(logf.DebugLevel).Info("Found no CertificateRequest resources owned by this Certificate for the current revision", "revision", *crt.Status.Revision)
		}
	}

	return Input{
		Certificate:            crt,
		CurrentRevisionRequest: req,
		Secret:                 secret,
	}, nil
}
