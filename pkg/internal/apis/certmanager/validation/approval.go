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

package validation

import (
	"context"
	"fmt"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	authzclient "k8s.io/client-go/kubernetes/typed/authorization/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/validation/util"
)

// ReviewApproval will review whether the client is able to approve or deny the
// given request, if indeed they are attempting to. A SubjectAccessReview will
// be performed if the client is attempting to approve/deny the request. An
// error will be returned if the SubjectAccessReview fails, or if they do not
// have permissions to perform the approval/denial.
func ReviewApproval(client authzclient.SubjectAccessReviewInterface,
	req *admissionv1.AdmissionRequest, oldObj, newObj runtime.Object) field.ErrorList {
	oldCR := oldObj.(*cmapi.CertificateRequest)
	newCR := newObj.(*cmapi.CertificateRequest)

	if !isApprovalRequest(oldCR, newCR) {
		return nil
	}

	ok, err := reviewRequest(client, req, newCR)
	if err != nil {
		return field.ErrorList{
			field.InternalError(field.NewPath("status.conditions"), err),
		}
	}

	if !ok {
		return field.ErrorList{
			field.Forbidden(field.NewPath("status.conditions"),
				fmt.Sprintf("user %q does not have permissions to set approved/denied conditions for issuer %v", req.UserInfo.Username, newCR.Spec.IssuerRef),
			),
		}
	}

	return nil
}

// reviewRequest will perform a SubjectAccessReview with the UserInfo fields of
// the client against the issuer of the CertificateRequest. A client must have
// the "approve" verb, for the resource "signer", at the Cluster scope, for the
// name "<issuer-kind>.<issuer-group>/<issuer-name>", or
// "<issuer-kind>.<issuer-group>/*".
func reviewRequest(client authzclient.SubjectAccessReviewInterface, req *admissionv1.AdmissionRequest, cr *cmapi.CertificateRequest) (bool, error) {
	extra := make(map[string]authzv1.ExtraValue)
	for k, v := range req.UserInfo.Extra {
		extra[k] = authzv1.ExtraValue(v)
	}

	kind := cr.Spec.IssuerRef.Kind
	if len(kind) == 0 {
		kind = cmapi.IssuerKind
	}

	group := cr.Spec.IssuerRef.Group
	if len(group) == 0 {
		group = certmanager.GroupName
	}

	for _, name := range []string{
		fmt.Sprintf("%s.%s/*", strings.ToLower(kind), group),
		fmt.Sprintf("%s.%s/%s", strings.ToLower(kind), group, cr.Spec.IssuerRef.Name),
	} {
		resp, err := client.Create(context.TODO(), &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:   req.UserInfo.Username,
				Groups: req.UserInfo.Groups,
				Extra:  extra,
				UID:    req.UserInfo.UID,

				ResourceAttributes: &authzv1.ResourceAttributes{
					Group:    certmanager.GroupName,
					Resource: "signers",
					Name:     name,
					Verb:     "approve",
					Version:  "*",
				},
			},
		}, metav1.CreateOptions{})
		if err != nil {
			return false, err
		}

		if resp.Status.Allowed {
			return true, nil
		}
	}

	return false, nil
}

// isApprovalRequest will return true if the request is given a new approved or
// denied condition. This check is strictly concerned with these conditions
// being _added_. We do this to reduce the number of SAR calls made, since
// removal or changing of these conditions will be rejected elsewhere in the
// validation chain locally.
func isApprovalRequest(oldCR, newCR *cmapi.CertificateRequest) bool {
	oldCRApproving := util.GetCertificateRequestCondition(oldCR.Status.Conditions, cmapi.CertificateRequestConditionApproved)
	newCRApproving := util.GetCertificateRequestCondition(newCR.Status.Conditions, cmapi.CertificateRequestConditionApproved)

	if oldCRApproving == nil && newCRApproving != nil {
		return true
	}

	oldCRDenying := util.GetCertificateRequestCondition(oldCR.Status.Conditions, cmapi.CertificateRequestConditionDenied)
	newCRDenying := util.GetCertificateRequestCondition(newCR.Status.Conditions, cmapi.CertificateRequestConditionDenied)

	if oldCRDenying == nil && newCRDenying != nil {
		return true
	}

	return false
}
