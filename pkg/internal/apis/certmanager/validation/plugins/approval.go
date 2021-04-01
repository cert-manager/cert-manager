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

package plugins

import (
	"context"
	"errors"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	authzclient "k8s.io/client-go/kubernetes/typed/authorization/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	internalcmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/validation/util"
)

// approval is responsible for reviewing whether users attempting to approve or
// deny a CertificateRequest have sufficient permissions to do so.
type approval struct {
	scheme *runtime.Scheme

	sarclient      authzclient.SubjectAccessReviewInterface
	discoverclient discovery.DiscoveryInterface
}

type signerResource struct {
	// signer resource name
	name       string
	group      string
	namespaced bool

	// name of the object for this signer
	signerName       string
	requestNamespace string
}

func newApproval(scheme *runtime.Scheme) *approval {
	return &approval{
		scheme: scheme,
	}
}

func (a *approval) Init(client kubernetes.Interface) {
	a.sarclient = client.AuthorizationV1().SubjectAccessReviews()
	a.discoverclient = client.Discovery()
}

// Validate will review whether the client is able to approve or deny the given
// request, if indeed they are attempting to. A SubjectAccessReview will be
// performed if the client is attempting to approve/deny the request. An error
// will be returned if the SubjectAccessReview fails, or if they do not have
// permissions to perform the approval/denial. The request will also fail if
// the referenced signer doesn't exist in this cluster.
func (a *approval) Validate(req *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) *field.Error {
	// Only perform validation on UPDATE operations
	if req.Operation != admissionv1.Update {
		return nil
	}

	// Only Validate over CertificateRequest resources
	if req.RequestKind.Group != certmanager.GroupName || req.RequestKind.Kind != cmapi.CertificateRequestKind {
		return nil
	}

	// Error if the clients are not initialised
	if a.sarclient == nil || a.discoverclient == nil {
		return internalError(errors.New("approval validation not initialised"))
	}

	gvk := schema.GroupVersionKind{
		Group:   req.RequestKind.Group,
		Version: runtime.APIVersionInternal,
		Kind:    req.RequestKind.Kind,
	}

	// Convert the incomming old and new CertificateRequest into the internal
	// version. This is so we can process a single type, reglardless of whatever
	// CertificateRequest version is in the request.
	for _, obj := range []runtime.Object{oldObj, obj} {
		internalObj, err := a.scheme.New(gvk)
		if err != nil {
			return internalError(err)
		}

		if err := a.scheme.Convert(obj, internalObj, nil); err != nil {
			return internalError(err)
		}
	}

	oldCR := oldObj.(*internalcmapi.CertificateRequest)
	newCR := obj.(*internalcmapi.CertificateRequest)

	// If the request is not for approval, exit early
	if !isApprovalRequest(oldCR, newCR) {
		return nil
	}

	// Get the referenced signer signer definition
	signer, ok, err := a.signerResource(newCR)
	if err != nil {
		return internalError(err)
	}
	if !ok {
		return field.Forbidden(field.NewPath("spec.issuerRef"),
			fmt.Sprintf("referenced signer resource does not exist: %v", newCR.Spec.IssuerRef))
	}

	// Construct the signer resource names that permissions should be granted
	// for
	names := a.signerResourceNames(signer)

	// Review whether the approving user has the correct permissions for the
	// given signer names
	ok, err = a.reviewRequest(req, names)
	if err != nil {
		return internalError(err)
	}

	if !ok {
		return field.Forbidden(field.NewPath("status.conditions"),
			fmt.Sprintf("user %q does not have permissions to set approved/denied conditions for issuer %v", req.UserInfo.Username, newCR.Spec.IssuerRef))
	}

	return nil
}

// reviewRequest will perform a SubjectAccessReview with the UserInfo fields of
// the client against the issuer of the CertificateRequest. A client must have
// the "approve" verb, for the resource "signer", at the Cluster scope, for the
// name "<signer-kind>.<signer-group>/[<signer-namespace.]<signer-name>", or
// "<signer-kind>.<signer-group>/*".
func (a *approval) reviewRequest(req *admissionv1.AdmissionRequest, names []string) (bool, error) {
	extra := make(map[string]authzv1.ExtraValue)
	for k, v := range req.UserInfo.Extra {
		extra[k] = authzv1.ExtraValue(v)
	}

	for _, name := range names {
		resp, err := a.sarclient.Create(context.TODO(), &authzv1.SubjectAccessReview{
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
func isApprovalRequest(oldCR, newCR *internalcmapi.CertificateRequest) bool {
	oldCRApproving := util.GetCertificateRequestCondition(oldCR.Status.Conditions, internalcmapi.CertificateRequestConditionApproved)
	newCRApproving := util.GetCertificateRequestCondition(newCR.Status.Conditions, internalcmapi.CertificateRequestConditionApproved)

	if oldCRApproving == nil && newCRApproving != nil {
		return true
	}

	oldCRDenying := util.GetCertificateRequestCondition(oldCR.Status.Conditions, internalcmapi.CertificateRequestConditionDenied)
	newCRDenying := util.GetCertificateRequestCondition(newCR.Status.Conditions, internalcmapi.CertificateRequestConditionDenied)

	if oldCRDenying == nil && newCRDenying != nil {
		return true
	}

	return false
}

// signerResourceNames returns a slice of the signer resource names that this
// signer can be represented as, given the request.
func (a *approval) signerResourceNames(signer *signerResource) []string {
	wildcard := fmt.Sprintf("%s.%s/*", signer.name, signer.group)

	named := fmt.Sprintf("%s.%s", signer.name, signer.group)
	if signer.namespaced {
		named = fmt.Sprintf("%s/%s.%s", named, signer.requestNamespace, signer.signerName)
	} else {
		named = fmt.Sprintf("%s/%s", named, signer.signerName)
	}

	return []string{wildcard, named}
}

// signerResource returns information about the singer resource in the cluster,
// using the discovery client. Returns false if the signer is not installed in
// the cluster.
func (a *approval) signerResource(cr *internalcmapi.CertificateRequest) (*signerResource, bool, error) {
	group := cr.Spec.IssuerRef.Group
	if len(group) == 0 {
		group = certmanager.GroupName
	}

	kind := cr.Spec.IssuerRef.Kind
	if len(kind) == 0 {
		kind = cmapi.IssuerKind
	}

	// Test for internal signer types and return accordingly
	if group == certmanager.GroupName {
		switch kind {
		case cmapi.IssuerKind:
			return &signerResource{
				name:             "issuers",
				group:            group,
				namespaced:       true,
				signerName:       cr.Spec.IssuerRef.Name,
				requestNamespace: cr.Namespace,
			}, true, nil

		case cmapi.ClusterIssuerKind:
			return &signerResource{
				name:             "clusterissuers",
				group:            group,
				namespaced:       false,
				signerName:       cr.Spec.IssuerRef.Name,
				requestNamespace: cr.Namespace,
			}, true, nil
		}
	}

	grouplist, err := a.discoverclient.ServerGroups()
	if err != nil {
		return nil, false, err
	}

	for _, resourceGroup := range grouplist.Groups {
		if group != resourceGroup.Name {
			continue
		}

		for _, version := range resourceGroup.Versions {
			resources, err := a.discoverclient.ServerResourcesForGroupVersion(version.GroupVersion)
			if err != nil {
				return nil, false, err
			}

			for _, resource := range resources.APIResources {
				if resource.Kind == kind {
					return &signerResource{
						name:             resource.Name,
						group:            group,
						namespaced:       resource.Namespaced,
						requestNamespace: cr.Namespace,
						signerName:       cr.Spec.IssuerRef.Name,
					}, true, nil
				}
			}
		}
	}

	return nil, false, nil
}

func internalError(err error) *field.Error {
	return field.InternalError(field.NewPath("status.conditions"), err)
}
