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

func (g *Gatherer) DataForCertificate(ctx context.Context, crt *cmapi.Certificate) (Input, error) {
	log := logf.FromContext(ctx)
	// Attempt to fetch the Secret being managed but tolerate NotFound errors.
	secret, err := g.SecretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if err != nil && !apierrors.IsNotFound(err) {
		return Input{}, err
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
