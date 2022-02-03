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
	"strings"
	"sync"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"

	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
	"github.com/cert-manager/cert-manager/internal/apis/certmanager/validation/util"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission/initializer"
)

const PluginName = "CertificateRequestApproval"

type certificateRequestApproval struct {
	*admission.Handler

	authorizer authorizer.Authorizer
	discovery  discovery.DiscoveryInterface

	// resourceCache stores the associated APIResource for a given GroupKind
	// to making multiple queries to the API server for every approval.
	resourceCache map[schema.GroupKind]metav1.APIResource
	mutex         sync.RWMutex
}

var _ admission.ValidationInterface = &certificateRequestApproval{}
var _ initializer.WantsAuthorizer = &certificateRequestApproval{}
var _ initializer.WantsExternalKubeClientSet = &certificateRequestApproval{}

func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func() (admission.Interface, error) {
		return NewPlugin(), nil
	})
}

func NewPlugin() admission.Interface {
	return &certificateRequestApproval{
		Handler:       admission.NewHandler(admissionv1.Update),
		resourceCache: map[schema.GroupKind]metav1.APIResource{},
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
	apiResource, err := c.apiResourceForGroupKind(schema.GroupKind{Group: group, Kind: kind})
	switch {
	case err == errNoResourceExists:
		return nil, field.Forbidden(field.NewPath("spec.issuerRef"),
			fmt.Sprintf("referenced signer resource does not exist: %v", cr.Spec.IssuerRef))
	case err != nil:
		return nil, err
	}

	signerName := signerNameForAPIResource(cr.Spec.IssuerRef.Name, cr.Namespace, *apiResource)
	if !isAuthorizedForSignerName(ctx, c.authorizer, userInfoForRequest(request), signerName) {
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
func (c *certificateRequestApproval) apiResourceForGroupKind(groupKind schema.GroupKind) (resource *metav1.APIResource, err error) {
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

				r := resource.DeepCopy()
				// the Group field is not always populated in responses, so explicitly set it
				r.Group = apiGroup.Name
				c.cacheAPIResource(groupKind, *r)
				return r, nil
			}
		}
	}

	return nil, errNoResourceExists
}

func (c *certificateRequestApproval) readAPIResourceFromCache(groupKind schema.GroupKind) *metav1.APIResource {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if resource, ok := c.resourceCache[groupKind]; ok {
		return &resource
	}
	return nil
}

func (c *certificateRequestApproval) cacheAPIResource(groupKind schema.GroupKind, resource metav1.APIResource) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.resourceCache[groupKind] = resource
}

var errNoResourceExists = fmt.Errorf("no resource registered")

// signerNameForAPIResource returns the computed signerName for a given API resource
// referenced by a CertificateRequest in a namespace.
func signerNameForAPIResource(name, namespace string, apiResource metav1.APIResource) string {
	if apiResource.Namespaced {
		return fmt.Sprintf("%s.%s/%s.%s", apiResource.Name, apiResource.Group, namespace, name)
	}
	return fmt.Sprintf("%s.%s/%s", apiResource.Name, apiResource.Group, name)
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

// isAuthorizedForSignerName checks whether an entity is authorized to 'approve' certificaterequests
// for a given signerName.
// We absorb errors from the authorizer because they are already retried by the underlying authorization
// client, so we shouldn't ever see them unless the context webhook doesn't have the ability to submit
// SARs or the context is cancelled (in which case, the AdmissionResponse won't ever be returned to the apiserver).
func isAuthorizedForSignerName(ctx context.Context, authz authorizer.Authorizer, info user.Info, signerName string) bool {
	verb := "approve"
	// First check if the user has explicit permission to 'approve' for the given signerName.
	attr := buildAttributes(info, verb, signerName)
	decision, _, err := authz.Authorize(ctx, attr)
	switch {
	case err != nil:
		return false
	case decision == authorizer.DecisionAllow:
		return true
	}

	// If not, check if the user has wildcard permissions to 'approve' for the domain portion of the signerName, e.g.
	// 'issuers.cert-manager.io/*'.
	attr = buildWildcardAttributes(info, verb, signerName)
	decision, _, err = authz.Authorize(ctx, attr)
	switch {
	case err != nil:
		return false
	case decision == authorizer.DecisionAllow:
		return true
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

func buildWildcardAttributes(info user.Info, verb, signerName string) authorizer.Attributes {
	parts := strings.Split(signerName, "/")
	domain := parts[0]
	return buildAttributes(info, verb, domain+"/*")
}

func (c *certificateRequestApproval) SetAuthorizer(a authorizer.Authorizer) {
	c.authorizer = a
}

func (c *certificateRequestApproval) SetExternalKubeClientSet(client kubernetes.Interface) {
	c.discovery = client.Discovery()
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
