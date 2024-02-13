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

import (
	"context"
	"fmt"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/discovery"

	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
	"github.com/cert-manager/cert-manager/internal/apis/meta"
	discoveryfake "github.com/cert-manager/cert-manager/test/unit/discovery"
)

var (
	expNoDiscovery = discovery.DiscoveryInterface(nil)
)

func TestValidate(t *testing.T) {
	baseCR := &certmanager.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Namespace: "testns"},
		Spec: certmanager.CertificateRequestSpec{
			IssuerRef: meta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "example.io",
			},
		},
	}

	approvedCR := baseCR.DeepCopy()
	approvedCR.Status = certmanager.CertificateRequestStatus{
		Conditions: []certmanager.CertificateRequestCondition{
			{
				Type:    certmanager.CertificateRequestConditionApproved,
				Status:  meta.ConditionTrue,
				Reason:  "cert-manager.io",
				Message: "",
			},
		},
	}

	var alwaysPanicAuthorizer *fakeAuthorizer
	tests := map[string]struct {
		req          *admissionv1.AdmissionRequest
		oldCR, newCR *certmanager.CertificateRequest

		authorizer     *fakeAuthorizer
		discoverclient discovery.DiscoveryInterface

		expErr error
	}{
		"if the request is not for CertificateRequest, exit nil": {
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Update,
				RequestResource: &metav1.GroupVersionResource{
					Group:    "cert-manager.io",
					Resource: "issuers",
				},
				RequestSubResource: "status",
			},
			authorizer:     alwaysPanicAuthorizer,
			discoverclient: expNoDiscovery,
			expErr:         nil,
		},
		"if the request is not for cert-manager.io, exit nil": {
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Update,
				RequestResource: &metav1.GroupVersionResource{
					Group:    "foo.cert-manager.io",
					Resource: "certificaterequests",
				},
				RequestSubResource: "status",
			},
			authorizer: alwaysPanicAuthorizer,
			expErr:     nil,
		},
		"if the CertificateRequest references a signer that doesn't exist, error": {
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Update,
				RequestResource: &metav1.GroupVersionResource{
					Group:    "cert-manager.io",
					Resource: "certificaterequests",
				},
				RequestSubResource: "status",
			},
			oldCR:      baseCR,
			newCR:      approvedCR,
			authorizer: alwaysPanicAuthorizer,
			discoverclient: discoveryfake.NewDiscovery().
				WithServerGroups(func() (*metav1.APIGroupList, error) {
					return &metav1.APIGroupList{}, nil
				}),
			expErr: field.Forbidden(field.NewPath("spec.issuerRef"),
				"referenced signer resource does not exist: {my-issuer Issuer example.io}"),
		},
		"if the CertificateRequest references a signer that the approver doesn't have permissions for, error": {
			req: &admissionv1.AdmissionRequest{
				UserInfo: authnv1.UserInfo{
					Username: "user-1",
				},
				Operation: admissionv1.Update,
				RequestResource: &metav1.GroupVersionResource{
					Group:    "cert-manager.io",
					Resource: "certificaterequests",
				},
				RequestSubResource: "status",
			},
			oldCR: baseCR,
			newCR: approvedCR,
			discoverclient: discoveryfake.NewDiscovery().
				WithServerGroups(func() (*metav1.APIGroupList, error) {
					return &metav1.APIGroupList{
						Groups: []metav1.APIGroup{
							{
								Name: "example.io",
								Versions: []metav1.GroupVersionForDiscovery{
									{GroupVersion: "example.io/a-version", Version: "a-version"},
								},
							},
						},
					}, nil
				}).
				WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
					return &metav1.APIResourceList{
						APIResources: []metav1.APIResource{
							{
								Name:       "issuers",
								Namespaced: true,
								Kind:       "Issuer",
							},
						},
					}, nil
				}),
			authorizer: &fakeAuthorizer{
				verb:        "approve",
				allowedName: "issuers.example.io/testns.my-issuer",
				decision:    authorizer.DecisionNoOpinion,
			},
			expErr: field.Forbidden(field.NewPath("status.conditions"),
				`user "user-1" does not have permissions to set approved/denied conditions for issuer {my-issuer Issuer example.io}`),
		},
		"if the CertificateRequest references a signer that the approver has permissions for, return nil": {
			req: &admissionv1.AdmissionRequest{
				UserInfo: authnv1.UserInfo{
					Username: "user-1",
				},
				Operation: admissionv1.Update,
				RequestResource: &metav1.GroupVersionResource{
					Group:    "cert-manager.io",
					Resource: "certificaterequests",
				},
				RequestSubResource: "status",
			},
			oldCR: baseCR,
			newCR: approvedCR,
			discoverclient: discoveryfake.NewDiscovery().
				WithServerGroups(func() (*metav1.APIGroupList, error) {
					return &metav1.APIGroupList{
						Groups: []metav1.APIGroup{
							{
								Name: "example.io",
								Versions: []metav1.GroupVersionForDiscovery{
									{GroupVersion: "example.io/a-version", Version: "a-version"},
								},
							},
						},
					}, nil
				}).
				WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
					return &metav1.APIResourceList{
						APIResources: []metav1.APIResource{
							{
								Name:       "issuers",
								Namespaced: true,
								Kind:       "Issuer",
							},
						},
					}, nil
				}),
			authorizer: &fakeAuthorizer{
				verb:        "approve",
				allowedName: "issuers.example.io/testns.my-issuer",
				decision:    authorizer.DecisionAllow,
			},
		},
		"if the CertificateRequest references a signer that the approver has permissions for the wildcard of, return nil": {
			req: &admissionv1.AdmissionRequest{
				UserInfo: authnv1.UserInfo{
					Username: "user-1",
				},
				Operation: admissionv1.Update,
				RequestResource: &metav1.GroupVersionResource{
					Group:    "cert-manager.io",
					Resource: "certificaterequests",
				},
				RequestSubResource: "status",
			},
			oldCR: baseCR,
			newCR: approvedCR,
			discoverclient: discoveryfake.NewDiscovery().
				WithServerGroups(func() (*metav1.APIGroupList, error) {
					return &metav1.APIGroupList{
						Groups: []metav1.APIGroup{
							{
								Name: "example.io",
								Versions: []metav1.GroupVersionForDiscovery{
									{GroupVersion: "example.io/a-version", Version: "a-version"},
								},
							},
						},
					}, nil
				}).
				WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
					return &metav1.APIResourceList{
						APIResources: []metav1.APIResource{
							{
								Name:       "issuers",
								Namespaced: true,
								Kind:       "Issuer",
							},
						},
					}, nil
				}),
			authorizer: &fakeAuthorizer{
				verb:        "approve",
				allowedName: "issuers.example.io/*",
				decision:    authorizer.DecisionAllow,
			},
		},
		"should error if the authorizer returns an error": {
			req: &admissionv1.AdmissionRequest{
				UserInfo: authnv1.UserInfo{
					Username: "user-1",
				},
				Operation: admissionv1.Update,
				RequestResource: &metav1.GroupVersionResource{
					Group:    "cert-manager.io",
					Resource: "certificaterequests",
				},
				RequestSubResource: "status",
			},
			oldCR: baseCR,
			newCR: approvedCR,
			discoverclient: discoveryfake.NewDiscovery().
				WithServerGroups(func() (*metav1.APIGroupList, error) {
					return &metav1.APIGroupList{
						Groups: []metav1.APIGroup{
							{
								Name: "example.io",
								Versions: []metav1.GroupVersionForDiscovery{
									{GroupVersion: "example.io/a-version", Version: "a-version"},
								},
							},
						},
					}, nil
				}).
				WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
					return &metav1.APIResourceList{
						APIResources: []metav1.APIResource{
							{
								Name:       "issuers",
								Namespaced: true,
								Kind:       "Issuer",
							},
						},
					}, nil
				}),
			authorizer: &fakeAuthorizer{
				err: fmt.Errorf("authorizer error"),
			},
			expErr: field.Forbidden(field.NewPath("status.conditions"),
				`user "user-1" does not have permissions to set approved/denied conditions for issuer {my-issuer Issuer example.io}`),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			a := NewPlugin(test.authorizer, test.discoverclient).(*certificateRequestApproval)
			if test.authorizer != nil {
				test.authorizer.t = t
			}

			warnings, err := a.Validate(context.TODO(), *test.req, test.oldCR, test.newCR)
			if len(warnings) > 0 {
				t.Errorf("expected no warnings but got: %v", warnings)
			}
			compareErrors(t, test.expErr, err)
		})
	}
}

type fakeAuthorizer struct {
	t           *testing.T
	verb        string
	allowedName string
	decision    authorizer.Decision
	err         error
}

func (f fakeAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	if f.err != nil {
		return f.decision, "forced error", f.err
	}
	if a.GetVerb() != f.verb {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised verb '%s'", a.GetVerb()), nil
	}
	if a.GetAPIGroup() != "cert-manager.io" {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised groupName '%s'", a.GetAPIGroup()), nil
	}
	if a.GetAPIVersion() != "*" {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised apiVersion '%s'", a.GetAPIVersion()), nil
	}
	if a.GetResource() != "signers" {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised resource '%s'", a.GetResource()), nil
	}
	if a.GetName() != f.allowedName {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised resource name '%s'", a.GetName()), nil
	}
	if !a.IsResourceRequest() {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised IsResourceRequest '%t'", a.IsResourceRequest()), nil
	}
	return f.decision, "", nil
}

func compareErrors(t *testing.T, exp, act error) {
	if exp == nil && act == nil {
		return
	}
	if exp == nil && act != nil ||
		exp != nil && act == nil ||
		exp.Error() != act.Error() {
		t.Errorf("error not as expected. exp=%v, act=%v", exp, act)
	}
}
