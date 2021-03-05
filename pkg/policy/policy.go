/*
Copyright 2021 The cert-manager Authors.

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

package policy

import (
	"context"
	"fmt"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	authzclient "k8s.io/client-go/kubernetes/typed/authorization/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmpolicylisters "github.com/jetstack/cert-manager/pkg/client/listers/policy/v1alpha1"
)

var (
	ErrorReason          = "EvaluationError"
	NoCRPExistReason     = "NoCertificateRequestPoliciesExist"
	MissingBindingReason = "NoCertificateRequestPoliciesBound"
)

// Policy is responsible for evaluating whether incoming CertificateRequests
// should be approved, checking CertificateRequestPolicys.
type Policy struct {
	lister   cmpolicylisters.CertificateRequestPolicyLister
	reviewer authzclient.SubjectAccessReviewInterface
}

func New(lister cmpolicylisters.CertificateRequestPolicyLister, reviewer authzclient.SubjectAccessReviewInterface) *Policy {
	return &Policy{
		lister:   lister,
		reviewer: reviewer,
	}
}

// Evaluate will evaluate whether the incoming CertificateRequest should be
// approved.
// - Consumers should consider a true response meaning the CertificateRequest
//   is **approved**.
// - Consumers should consider a false response and no error to mean the
//   CertificateRequest is **denied**.
// - Consumers should treat any error response as marking the
//   CertificateRequest as neither approved nor denied, and may consider
//   reevaluation at a later time.
func (p *Policy) Evaluate(ctx context.Context, cr *cmapi.CertificateRequest) (bool, string, error) {
	crps, err := p.lister.List(labels.Everything())
	if err != nil {
		return false, ErrorReason, err
	}

	// If no CertificateRequestPolicys exist, exit early approved
	if len(crps) == 0 {
		return true, NoCRPExistReason, nil
	}

	policyErrors := make(map[string]string)

	// Check namespaced scope, then cluster scope
	for _, ns := range []string{cr.Namespace, ""} {
		for _, crp := range crps {

			// Don't check the same CertificateRequestPolicy more than once
			if _, ok := policyErrors[crp.Name]; ok {
				continue
			}

			// Perform subject access review for this CertificateRequestPolicy
			resp, err := p.reviewer.Create(ctx, &authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					//User: cr.Spec.Username,
					//Groups: cr.Spec.Groups,
					//Extra: cr.Spec.Extra,
					//UID: cr.Spec.UID,

					ResourceAttributes: &authzv1.ResourceAttributes{
						Group:     "policy.cert-manager.io",
						Resource:  "CertificateRequestPolicys",
						Name:      crp.Name,
						Namespace: ns,
					},

					NonResourceAttributes: &authzv1.NonResourceAttributes{
						Verb: "use",
					},
				},
			}, metav1.CreateOptions{})
			if err != nil {
				return false, ErrorReason, err
			}

			// Don't perform evaluation if this CertificateRequestPolicy is not bound
			if !resp.Status.Allowed {
				continue
			}

			var el field.ErrorList
			if err := EvaluateCertificateRequest(&el, crp, cr); err != nil {
				return false, ErrorReason, err
			}

			// If no evaluation errors resulting from this policy, return approved
			// with the name of the CertificateRequestPolicy.
			if len(el) == 0 {
				return true, crp.Name, nil
			}

			// Collect policy errors by the CertificateRequestPolicy name, so errors
			// can be bubbled to the CertificateRequest condition
			policyErrors[crp.Name] = el.ToAggregate().Error()
		}
	}

	// If policies exist, but none are bound
	if len(policyErrors) == 0 {
		return false, MissingBindingReason, nil
	}

	// Return with all policies that we consulted, and their errors to why the
	// request was denied.
	return false, fmt.Sprintf("No policy approved this request: %v", policyErrors), nil
}
