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

package approval

// CertificateRequestApproval is a plugin that ensures entities that are attempting to
// modify `status.conditions[type="Approved"]` or `status.conditions[type="Denied"]`
// have permission to do so (granted via RBAC).
// Entities will need to be able to `approve` (verb) `signers` (resource type) in
// `cert-manager.io` (group) with the name `<issuer-type>.<issuer-group>/[<certificaterequest-namespace>.]<issuer-name>`.
// For example: `issuers.cert-manager.io/my-namespace.my-issuer-name`.
// A wildcard signerName format is also supported: `issuers.cert-manager.io/*`.

import (
	"context"
	"fmt"
	"sync"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/discovery"

	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
	"github.com/cert-manager/cert-manager/internal/apis/certmanager/validation/util"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
)

type certificateRequestApproval struct {
	*admission.Handler

	authorizer authorizer.Authorizer
	discovery  discovery.DiscoveryInterface

	// resourceInfo stores the associated resource info for a given GroupKind
	// to prevent making multiple queries to the API server for every approval.
	resourceInfo map[schema.GroupKind]resourceInfo
	mutex        sync.RWMutex
}

type resourceInfo struct {
	schema.GroupResource
	Namespaced bool
}

var _ admission.ValidationInterface = &certificateRequestApproval{}

func NewPlugin(authz authorizer.Authorizer, discoveryClient discovery.DiscoveryInterface) admission.Interface {
	return &certificateRequestApproval{
		Handler:      admission.NewHandler(admissionv1.Update),
		resourceInfo: map[schema.GroupKind]resourceInfo{},

		authorizer: authz,
		discovery:  discoveryClient,
	}
}

func (c *certificateRequestApproval) Validate(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (warnings []string, err error) {
	if request.RequestResource.Group != "cert-manager.io" ||
		request.RequestResource.Resource != "certificaterequests" ||
		request.RequestSubResource != "status" {
		return nil, nil
	}

	oldCR, cr := oldObj.(*certmanager.CertificateRequest), obj.(*certmanager.CertificateRequest)
	if !approvalConditionsHaveChanged(oldCR, cr) {
		return nil, nil
	}

	group := cr.Spec.IssuerRef.Group
	kind := cr.Spec.IssuerRef.Kind
	// TODO: move this defaulting into the Scheme (registered as default functions) so
	//       these will be set when the CertificateRequest is decoded.
	if group == "" {
		group = "cert-manager.io"
	}
	if kind == "" {
		kind = "Issuer"
	}

	// We got the GroupKind, now we need to get the Resource name.
	apiResource, err := c.apiResourceForGroupKind(schema.GroupKind{Group: group, Kind: kind})
	switch {
	case err == errNoResourceExists:
		return nil, field.Forbidden(field.NewPath("spec.issuerRef"),
			fmt.Sprintf("referenced signer resource does not exist: %v", cr.Spec.IssuerRef))
	case err != nil:
		return nil, err
	}

	signerNames := signerNamesForAPIResource(cr.Spec.IssuerRef.Name, cr.Namespace, *apiResource)
	if !isAuthorizedForSignerNames(ctx, c.authorizer, userInfoForRequest(request), signerNames) {
		return nil, field.Forbidden(field.NewPath("status.conditions"),
			fmt.Sprintf("user %q does not have permissions to set approved/denied conditions for issuer %v", request.UserInfo.Username, cr.Spec.IssuerRef))
	}

	return nil, nil
}

// approvalConditionsHaveChanged returns true if either the Approved or Denied conditions
// have been added to the CertificateRequest.
func approvalConditionsHaveChanged(oldCR, cr *certmanager.CertificateRequest) bool {
	oldCRApproving := util.GetCertificateRequestCondition(oldCR.Status.Conditions, certmanager.CertificateRequestConditionApproved)
	newCRApproving := util.GetCertificateRequestCondition(cr.Status.Conditions, certmanager.CertificateRequestConditionApproved)
	oldCRDenying := util.GetCertificateRequestCondition(oldCR.Status.Conditions, certmanager.CertificateRequestConditionDenied)
	newCRDenying := util.GetCertificateRequestCondition(cr.Status.Conditions, certmanager.CertificateRequestConditionDenied)
	return (oldCRApproving == nil && newCRApproving != nil) || (oldCRDenying == nil && newCRDenying != nil)
}

// apiResourceForGroupKind returns the metav1.APIResource descriptor for a given GroupKind.
// This is required to properly construct the `signerName` used as part of validating
// requests that approve or deny the CertificateRequest.
// namespaced will be true if the resource is namespaced.
// 'resource' may be nil even if err is also nil.
func (c *certificateRequestApproval) apiResourceForGroupKind(groupKind schema.GroupKind) (info *resourceInfo, err error) {
	// fast path if resource is in the cache already
	if resource := c.readAPIResourceFromCache(groupKind); resource != nil {
		return resource, nil
	}

	// otherwise, query the apiserver
	// TODO: we should enhance caching here to avoid performing discovery queries
	//       many times if many CertificateRequest resources exist that reference
	//       a resource that doesn't exist
	groups, err := c.discovery.ServerGroups()
	if err != nil {
		return nil, err
	}

	for _, apiGroup := range groups.Groups {
		if apiGroup.Name != groupKind.Group {
			continue
		}

		for _, version := range apiGroup.Versions {
			apiResources, err := c.discovery.ServerResourcesForGroupVersion(version.GroupVersion)
			if err != nil {
				return nil, err
			}

			for _, resource := range apiResources.APIResources {
				if resource.Kind != groupKind.Kind {
					continue
				}

				return c.cacheAPIResource(groupKind, resource.Name, resource.Namespaced), nil
			}
		}
	}

	return nil, errNoResourceExists
}

func (c *certificateRequestApproval) readAPIResourceFromCache(groupKind schema.GroupKind) *resourceInfo {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if info, ok := c.resourceInfo[groupKind]; ok {
		return &info
	}
	return nil
}

func (c *certificateRequestApproval) cacheAPIResource(groupKind schema.GroupKind, resourceName string, namespaced bool) *resourceInfo {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	info := resourceInfo{
		GroupResource: schema.GroupResource{
			Group:    groupKind.Group,
			Resource: resourceName,
		},
		Namespaced: namespaced,
	}

	c.resourceInfo[groupKind] = info

	return &info
}

var errNoResourceExists = fmt.Errorf("no resource registered")

// signerNamesForAPIResource returns the computed signerName for a given API resource
// referenced by a CertificateRequest in a namespace.
func signerNamesForAPIResource(name, namespace string, info resourceInfo) []string {
	signerNames := make([]string, 0, 2)

	signerNames = append(signerNames, fmt.Sprintf("%s.%s/*", info.Resource, info.Group))

	if info.Namespaced {
		signerNames = append(signerNames, fmt.Sprintf("%s.%s/%s.%s", info.Resource, info.Group, namespace, name))
	} else {
		signerNames = append(signerNames, fmt.Sprintf("%s.%s/%s", info.Resource, info.Group, name))
	}

	return signerNames
}

// userInfoForRequest constructs a user.Info suitable for using with the authorizer interface
// from an AdmissionRequest.
func userInfoForRequest(req admissionv1.AdmissionRequest) user.Info {
	extra := make(map[string][]string)
	for k, v := range req.UserInfo.Extra {
		extra[k] = v
	}
	return &user.DefaultInfo{
		Name:   req.UserInfo.Username,
		UID:    req.UserInfo.UID,
		Groups: req.UserInfo.Groups,
		Extra:  extra,
	}
}

// isAuthorizedForSignerNames checks whether an entity is authorized to 'approve' certificaterequests
// for a given set of signerNames.
// We absorb errors from the authorizer because they are already retried by the underlying authorization
// client, so we shouldn't ever see them unless the context webhook doesn't have the ability to submit
// SARs or the context is cancelled (in which case, the AdmissionResponse won't ever be returned to the apiserver).
func isAuthorizedForSignerNames(ctx context.Context, authz authorizer.Authorizer, info user.Info, signerNames []string) bool {
	verb := "approve"

	for _, signerName := range signerNames {
		attr := buildAttributes(info, verb, signerName)
		decision, _, err := authz.Authorize(ctx, attr)
		switch {
		case err != nil:
			return false
		case decision == authorizer.DecisionAllow:
			return true
		}
	}

	return false
}

func buildAttributes(info user.Info, verb, signerName string) authorizer.Attributes {
	return authorizer.AttributesRecord{
		User:            info,
		Verb:            verb,
		Name:            signerName,
		APIGroup:        "cert-manager.io",
		APIVersion:      "*",
		Resource:        "signers",
		ResourceRequest: true,
	}
}

func (c *certificateRequestApproval) ValidateInitialization() error {
	if c.authorizer == nil {
		return fmt.Errorf("authorizer not set")
	}
	if c.discovery == nil {
		return fmt.Errorf("discovery client not set")
	}
	_, err := c.discovery.ServerGroups()
	if err != nil {
		return err
	}
	return nil
}
