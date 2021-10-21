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
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/discovery"
	kubefake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	internalcmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	internalcmmeta "github.com/jetstack/cert-manager/pkg/internal/apis/meta"
	"github.com/jetstack/cert-manager/pkg/webhook"
	discoveryfake "github.com/jetstack/cert-manager/test/unit/discovery"
)

var (
	expNoServerGroups = func(t *testing.T) func() (*metav1.APIGroupList, error) {
		return func() (*metav1.APIGroupList, error) {
			t.Fatal("unexpected ServerGroups call")
			return nil, nil
		}
	}

	expNoServerResourcesForGroupVersion = func(t *testing.T) func(string) (*metav1.APIResourceList, error) {
		return func(groupVersion string) (*metav1.APIResourceList, error) {
			t.Fatal("unexpected ServerResourcesForGroupVersion call")
			return nil, nil
		}
	}

	expNoDiscovery = func(t *testing.T) discovery.DiscoveryInterface {
		return discoveryfake.NewDiscovery().
			WithServerGroups(expNoServerGroups(t)).
			WithServerResourcesForGroupVersion(expNoServerResourcesForGroupVersion(t))
	}
)

func TestValidate(t *testing.T) {
	baseCR := &internalcmapi.CertificateRequest{}

	approvedCR := &internalcmapi.CertificateRequest{
		Spec: internalcmapi.CertificateRequestSpec{
			IssuerRef: internalcmmeta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "example.io",
			},
		},
		Status: internalcmapi.CertificateRequestStatus{
			Conditions: []internalcmapi.CertificateRequestCondition{
				{
					Type:    internalcmapi.CertificateRequestConditionApproved,
					Status:  internalcmmeta.ConditionTrue,
					Reason:  "cert-manager.io",
					Message: "",
				},
			},
		},
	}

	expNoSARReaction := func(t *testing.T) coretesting.ReactionFunc {
		return func(_ coretesting.Action) (bool, runtime.Object, error) {
			t.Fatal("unexpected call")
			return true, nil, nil
		}
	}

	tests := map[string]struct {
		req          *admissionv1.AdmissionRequest
		oldCR, newCR *internalcmapi.CertificateRequest

		sarreaction    func(t *testing.T) coretesting.ReactionFunc
		discoverclient func(t *testing.T) discovery.DiscoveryInterface

		expErr *field.Error
	}{
		"if the request is not an UPDATE operation, exit nil": {
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				RequestKind: &metav1.GroupVersionKind{
					Group: "cert-manager.io",
					Kind:  "CertificateRequest",
				},
			},
			sarreaction:    expNoSARReaction,
			discoverclient: expNoDiscovery,
			expErr:         nil,
		},
		"if the request is not for CertificateRequest, exit nil": {
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Update,
				RequestKind: &metav1.GroupVersionKind{
					Group: "cert-manager.io",
					Kind:  "Issuers",
				},
			},
			sarreaction:    expNoSARReaction,
			discoverclient: expNoDiscovery,
			expErr:         nil,
		},
		"if the request is not for cert-manager.io, exit nil": {
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Update,
				RequestKind: &metav1.GroupVersionKind{
					Group: "foo.cert-manager.io",
					Kind:  "CertificateRequest",
				},
			},
			sarreaction:    expNoSARReaction,
			discoverclient: expNoDiscovery,
			expErr:         nil,
		},
		"if the CertificateRequest references a signer that doesn't exist, error": {
			req: &admissionv1.AdmissionRequest{
				Operation: admissionv1.Update,
				RequestKind: &metav1.GroupVersionKind{
					Group: "cert-manager.io",
					Kind:  "CertificateRequest",
				},
			},
			oldCR:       baseCR,
			newCR:       approvedCR,
			sarreaction: expNoSARReaction,
			discoverclient: func(t *testing.T) discovery.DiscoveryInterface {
				return discoveryfake.NewDiscovery().
					WithServerGroups(func() (*metav1.APIGroupList, error) {
						return &metav1.APIGroupList{
							Groups: []metav1.APIGroup{
								{Name: "foo"},
								{Name: "bar"},
							},
						}, nil
					}).
					WithServerResourcesForGroupVersion(expNoServerResourcesForGroupVersion(t))
			},
			expErr: field.Forbidden(field.NewPath("spec.issuerRef"),
				"referenced signer resource does not exist: {my-issuer Issuer example.io}"),
		},
		"if the CertificateRequest references a signer that the approver doesn't have permissions for, error": {
			req: &admissionv1.AdmissionRequest{
				UserInfo: authnv1.UserInfo{
					Username: "user-1",
				},
				Operation: admissionv1.Update,
				RequestKind: &metav1.GroupVersionKind{
					Group: "cert-manager.io",
					Kind:  "CertificateRequest",
				},
			},
			oldCR: baseCR,
			newCR: approvedCR,
			discoverclient: func(t *testing.T) discovery.DiscoveryInterface {
				return discoveryfake.NewDiscovery().
					WithServerGroups(func() (*metav1.APIGroupList, error) {
						return &metav1.APIGroupList{
							Groups: []metav1.APIGroup{
								{Name: "example.io", Versions: []metav1.GroupVersionForDiscovery{
									{GroupVersion: "foo-bar"},
								}},
							},
						}, nil
					}).
					WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
						if groupVersion != "foo-bar" {
							t.Errorf("unexpected group version string: %s", groupVersion)
						}
						return &metav1.APIResourceList{
							APIResources: []metav1.APIResource{
								{
									Kind: "hello-world",
								},
								{
									Namespaced: true,
									Name:       "issuers",
									Kind:       "Issuer",
								},
							},
						}, nil
					})
			},
			sarreaction: func(t *testing.T) coretesting.ReactionFunc {
				return func(action coretesting.Action) (bool, runtime.Object, error) {
					return true, &authzv1.SubjectAccessReview{
						Status: authzv1.SubjectAccessReviewStatus{
							Allowed: false,
						},
					}, nil
				}
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
				RequestKind: &metav1.GroupVersionKind{
					Group: "cert-manager.io",
					Kind:  "CertificateRequest",
				},
			},
			oldCR: baseCR,
			newCR: approvedCR,
			discoverclient: func(t *testing.T) discovery.DiscoveryInterface {
				return discoveryfake.NewDiscovery().
					WithServerGroups(func() (*metav1.APIGroupList, error) {
						return &metav1.APIGroupList{
							Groups: []metav1.APIGroup{
								{Name: "example.io", Versions: []metav1.GroupVersionForDiscovery{
									{GroupVersion: "foo-bar"},
								}},
							},
						}, nil
					}).
					WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
						if groupVersion != "foo-bar" {
							t.Errorf("unexpected group version string: %s", groupVersion)
						}
						return &metav1.APIResourceList{
							APIResources: []metav1.APIResource{
								{
									Kind: "hello-world",
								},
								{
									Namespaced: true,
									Name:       "issuers",
									Kind:       "Issuer",
								},
							},
						}, nil
					})
			},
			sarreaction: func(t *testing.T) coretesting.ReactionFunc {
				return func(action coretesting.Action) (bool, runtime.Object, error) {
					return true, &authzv1.SubjectAccessReview{
						Status: authzv1.SubjectAccessReviewStatus{
							Allowed: true,
						},
					}, nil
				}
			},
			expErr: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := kubefake.NewSimpleClientset()
			client.Fake.PrependReactor("*", "*", test.sarreaction(t))

			a := approval{
				scheme:         webhook.Scheme,
				sarclient:      client.AuthorizationV1().SubjectAccessReviews(),
				discoverclient: test.discoverclient(t),
			}

			err := a.Validate(context.TODO(), test.req, test.oldCR, test.newCR)
			if !reflect.DeepEqual(test.expErr, err) {
				t.Errorf("unexpected error, exp=%#+v got=%#+v",
					test.expErr, err)
			}
		})
	}
}

func TestReviewRequest(t *testing.T) {
	userInfo := authnv1.UserInfo{
		Username: "user-1",
		Groups:   []string{"group-1", "group-2"},
		UID:      "abc1",
		Extra: map[string]authnv1.ExtraValue{
			"foo": {"123", "456"},
			"bar": {"789", "000"},
		},
	}

	verifyRequestUserInfo := func(t *testing.T, action coretesting.Action) {
		sar := action.(coretesting.CreateActionImpl).Object.(*authzv1.SubjectAccessReview)
		if sar.Spec.User != "user-1" ||
			!reflect.DeepEqual(sar.Spec.Groups, []string{"group-1", "group-2"}) ||
			sar.Spec.UID != "abc1" ||
			!reflect.DeepEqual(sar.Spec.Extra, map[string]authzv1.ExtraValue{
				"foo": {"123", "456"},
				"bar": {"789", "000"},
			}) {
			t.Errorf("got unexpected review userinfo: %#+v", sar.Spec)
		}
	}

	tests := map[string]struct {
		names    []string
		reaction func(t *testing.T) coretesting.ReactionFunc

		expOK, expErr bool
	}{
		"if no names given, expect no calls and return false": {
			names: []string{},
			reaction: func(t *testing.T) coretesting.ReactionFunc {
				return func(_ coretesting.Action) (bool, runtime.Object, error) {
					t.Fatal("unexpected call")
					return true, nil, nil
				}
			},
			expOK:  false,
			expErr: false,
		},
		"if SAR returns error, return error": {
			names: []string{
				"issuers.cert-manager.io/*",
				"issuers.cert-manager.io/sandbox.my-issuer",
			},
			reaction: func(t *testing.T) coretesting.ReactionFunc {
				return func(action coretesting.Action) (bool, runtime.Object, error) {
					verifyRequestUserInfo(t, action)
					return true, nil, errors.New("this is an error")
				}
			},
			expOK:  false,
			expErr: true,
		},
		"if both SARs returns false, return false": {
			names: []string{
				"issuers.cert-manager.io/*",
				"issuers.cert-manager.io/sandbox.my-issuer",
			},
			reaction: func(t *testing.T) coretesting.ReactionFunc {
				return func(action coretesting.Action) (bool, runtime.Object, error) {
					verifyRequestUserInfo(t, action)
					return true, &authzv1.SubjectAccessReview{
						Status: authzv1.SubjectAccessReviewStatus{
							Allowed: false,
						},
					}, nil
				}
			},
			expOK:  false,
			expErr: false,
		},
		"if first sar returns true, return ok": {
			names: []string{
				"issuers.cert-manager.io/*",
				"issuers.cert-manager.io/sandbox.my-issuer",
			},
			reaction: func(t *testing.T) coretesting.ReactionFunc {
				return func(action coretesting.Action) (bool, runtime.Object, error) {
					verifyRequestUserInfo(t, action)

					sar := action.(coretesting.CreateActionImpl).Object.(*authzv1.SubjectAccessReview)
					switch sar.Spec.ResourceAttributes.Name {
					case "issuers.cert-manager.io/*":
						return true, &authzv1.SubjectAccessReview{
							Status: authzv1.SubjectAccessReviewStatus{
								Allowed: true,
							},
						}, nil

					default:
						t.Fatalf("unexpected sar call: %#+v\n", sar.Spec)
						return true, nil, nil
					}
				}
			},
			expOK:  true,
			expErr: false,
		},
		"if second sar returns true, return true": {
			names: []string{
				"issuers.cert-manager.io/*",
				"issuers.cert-manager.io/sandbox.my-issuer",
			},
			reaction: func(t *testing.T) coretesting.ReactionFunc {
				return func(action coretesting.Action) (bool, runtime.Object, error) {
					verifyRequestUserInfo(t, action)

					sar := action.(coretesting.CreateActionImpl).Object.(*authzv1.SubjectAccessReview)
					switch sar.Spec.ResourceAttributes.Name {
					case "issuers.cert-manager.io/*":
						return true, &authzv1.SubjectAccessReview{
							Status: authzv1.SubjectAccessReviewStatus{
								Allowed: false,
							},
						}, nil

					case "issuers.cert-manager.io/sandbox.my-issuer":
						return true, &authzv1.SubjectAccessReview{
							Status: authzv1.SubjectAccessReviewStatus{
								Allowed: true,
							},
						}, nil

					default:
						t.Fatalf("unexpected sar call: %#+v\n", sar.Spec)
						return true, nil, nil
					}
				}
			},
			expOK:  true,
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := kubefake.NewSimpleClientset()
			client.Fake.PrependReactor("*", "*", test.reaction(t))

			a := &approval{
				sarclient: client.AuthorizationV1().SubjectAccessReviews(),
			}

			req := &admissionv1.AdmissionRequest{UserInfo: userInfo}
			ok, err := a.reviewRequest(context.TODO(), req, test.names)
			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v",
					test.expErr, err)
			}

			if ok != test.expOK {
				t.Errorf("unexpected ok, exp=%t got=%t",
					test.expOK, ok)
			}
		})
	}
}

func TestIsApprovalRequest(t *testing.T) {
	baseCR := &internalcmapi.CertificateRequest{}

	approvedCR := &internalcmapi.CertificateRequest{
		Status: internalcmapi.CertificateRequestStatus{
			Conditions: []internalcmapi.CertificateRequestCondition{
				{
					Type:    internalcmapi.CertificateRequestConditionApproved,
					Status:  internalcmmeta.ConditionTrue,
					Reason:  "cert-manager.io",
					Message: "",
				},
			},
		},
	}

	deniedCR := &internalcmapi.CertificateRequest{
		Status: internalcmapi.CertificateRequestStatus{
			Conditions: []internalcmapi.CertificateRequestCondition{
				{
					Type:    internalcmapi.CertificateRequestConditionDenied,
					Status:  internalcmmeta.ConditionTrue,
					Reason:  "cert-manager.io",
					Message: "",
				},
			},
		},
	}

	tests := map[string]struct {
		oldCR, newCR *internalcmapi.CertificateRequest
		expIs        bool
	}{
		"if no approval condition change, then return false": {
			oldCR: baseCR,
			newCR: baseCR,
			expIs: false,
		},
		"if approval condition added, then return true": {
			oldCR: baseCR,
			newCR: approvedCR,
			expIs: true,
		},
		"if denied condition added, then return true": {
			oldCR: baseCR,
			newCR: deniedCR,
			expIs: true,
		},
		"if both old and new approved, return false": {
			oldCR: approvedCR,
			newCR: approvedCR,
			expIs: false,
		},
		"if both old and new denied, return false": {
			oldCR: deniedCR,
			newCR: deniedCR,
			expIs: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			is := isApprovalRequest(test.oldCR, test.newCR)
			if test.expIs != is {
				t.Errorf("unexpected isApprovalRequest response, exp=%t got=%t",
					test.expIs, is)
			}
		})
	}
}

func TestSignerResource(t *testing.T) {
	tests := map[string]struct {
		request *internalcmapi.CertificateRequest

		client        func(t *testing.T) discovery.DiscoveryInterface
		expSigner     *signerResource
		expOK, expErr bool
	}{
		"if no group or kind, return internal signer resource for issuers.cert-manager.io": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Name: "my-issuer",
					},
				},
			},
			client: expNoDiscovery,
			expSigner: &signerResource{
				name:             "issuers",
				group:            "cert-manager.io",
				namespaced:       true,
				signerName:       "my-issuer",
				requestNamespace: "test-ns",
			},
			expOK:  true,
			expErr: false,
		},
		"if no group with kind Issuer, return internal signer resource for issuers.cert-manager.io": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Kind: "Issuer",
						Name: "my-issuer",
					},
				},
			},
			client: expNoDiscovery,
			expSigner: &signerResource{
				name:             "issuers",
				group:            "cert-manager.io",
				namespaced:       true,
				signerName:       "my-issuer",
				requestNamespace: "test-ns",
			},
			expOK:  true,
			expErr: false,
		},
		"if no kind with group cert-manager.io, return internal signer resource for issuers.cert-manager.io": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Group: "cert-manager.io",
						Name:  "my-issuer",
					},
				},
			},
			client: expNoDiscovery,
			expSigner: &signerResource{
				name:             "issuers",
				group:            "cert-manager.io",
				namespaced:       true,
				signerName:       "my-issuer",
				requestNamespace: "test-ns",
			},
			expOK:  true,
			expErr: false,
		},
		"if cert-manager.io Issuer, should return internal signer resource": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Group: "cert-manager.io",
						Kind:  "Issuer",
						Name:  "my-issuer",
					},
				},
			},
			client: expNoDiscovery,
			expSigner: &signerResource{
				name:             "issuers",
				group:            "cert-manager.io",
				namespaced:       true,
				signerName:       "my-issuer",
				requestNamespace: "test-ns",
			},
			expOK:  true,
			expErr: false,
		},
		"if no group with ClusterIssuer, return internal signer resource for clusterissuers.cert-manager.io": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Kind: "ClusterIssuer",
						Name: "my-issuer",
					},
				},
			},
			client: expNoDiscovery,
			expSigner: &signerResource{
				name:             "clusterissuers",
				group:            "cert-manager.io",
				namespaced:       false,
				signerName:       "my-issuer",
				requestNamespace: "test-ns",
			},
			expOK:  true,
			expErr: false,
		},
		"if kind ClusterIssuer group cert-manager.io, return internal signer resource for clusterissuers.cert-manager.io": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Group: "cert-manager.io",
						Kind:  "ClusterIssuer",
						Name:  "my-issuer",
					},
				},
			},
			expSigner: &signerResource{
				name:             "clusterissuers",
				group:            "cert-manager.io",
				namespaced:       false,
				signerName:       "my-issuer",
				requestNamespace: "test-ns",
			},
			client: expNoDiscovery,
			expOK:  true,
			expErr: false,
		},
		"if external group where the groups call errors, return error": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Group: "example.io",
						Kind:  "MyClusterIssuer",
						Name:  "my-issuer",
					},
				},
			},

			client: func(t *testing.T) discovery.DiscoveryInterface {
				return discoveryfake.NewDiscovery().
					WithServerGroups(func() (*metav1.APIGroupList, error) {
						return nil, errors.New("this is an error")
					}).
					WithServerResourcesForGroupVersion(expNoServerResourcesForGroupVersion(t))
			},
			expSigner: nil,
			expOK:     false,
			expErr:    true,
		},
		"if external group is not registered, then return false": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Group: "example.io",
						Kind:  "MyClusterIssuer",
						Name:  "my-issuer",
					},
				},
			},

			client: func(t *testing.T) discovery.DiscoveryInterface {
				return discoveryfake.NewDiscovery().
					WithServerGroups(func() (*metav1.APIGroupList, error) {
						return &metav1.APIGroupList{
							Groups: []metav1.APIGroup{
								{Name: "foo"},
								{Name: "bar"},
							},
						}, nil
					}).
					WithServerResourcesForGroupVersion(expNoServerResourcesForGroupVersion(t))
			},
			expSigner: nil,
			expOK:     false,
			expErr:    false,
		},
		"if external group is registered, but server resources call errors, error": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Group: "example.io",
						Kind:  "MyClusterIssuer",
						Name:  "my-issuer",
					},
				},
			},

			client: func(t *testing.T) discovery.DiscoveryInterface {
				return discoveryfake.NewDiscovery().
					WithServerGroups(func() (*metav1.APIGroupList, error) {
						return &metav1.APIGroupList{
							Groups: []metav1.APIGroup{
								{Name: "foo"},
								{Name: "bar"},
								{Name: "example.io", Versions: []metav1.GroupVersionForDiscovery{
									{GroupVersion: "foo-bar"},
								}},
							},
						}, nil
					}).
					WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
						if groupVersion != "foo-bar" {
							t.Errorf("unexpected group version string: %s", groupVersion)
						}
						return nil, errors.New("this is an error")
					})
			},
			expSigner: nil,
			expOK:     false,
			expErr:    true,
		},
		"if external group is registered, but server resources kind is not, return false": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Group: "example.io",
						Kind:  "MyClusterIssuer",
						Name:  "my-issuer",
					},
				},
			},

			client: func(t *testing.T) discovery.DiscoveryInterface {
				return discoveryfake.NewDiscovery().
					WithServerGroups(func() (*metav1.APIGroupList, error) {
						return &metav1.APIGroupList{
							Groups: []metav1.APIGroup{
								{Name: "foo"},
								{Name: "bar"},
								{Name: "example.io", Versions: []metav1.GroupVersionForDiscovery{
									{GroupVersion: "foo-bar"},
									{GroupVersion: "bar-foo"},
								}},
							},
						}, nil
					}).
					WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
						if groupVersion != "foo-bar" && groupVersion != "bar-foo" {
							t.Errorf("unexpected group version string: %s", groupVersion)
						}
						return &metav1.APIResourceList{
							APIResources: []metav1.APIResource{
								{
									Kind: "hello-world",
								},
								{
									Kind: "NotMyClusterIssuer",
								},
							},
						}, nil
					})
			},
			expSigner: nil,
			expOK:     false,
			expErr:    false,
		},
		"if external group is registered, and server resources kind exists and namespaced, return namespaced signer": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Group: "example.io",
						Kind:  "MyClusterIssuer",
						Name:  "my-issuer",
					},
				},
			},

			client: func(t *testing.T) discovery.DiscoveryInterface {
				return discoveryfake.NewDiscovery().
					WithServerGroups(func() (*metav1.APIGroupList, error) {
						return &metav1.APIGroupList{
							Groups: []metav1.APIGroup{
								{Name: "foo"},
								{Name: "bar"},
								{Name: "example.io", Versions: []metav1.GroupVersionForDiscovery{
									{GroupVersion: "foo-bar"},
									{GroupVersion: "bar-foo"},
								}},
							},
						}, nil
					}).
					WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
						if groupVersion != "foo-bar" && groupVersion != "bar-foo" {
							t.Errorf("unexpected group version string: %s", groupVersion)
						}
						return &metav1.APIResourceList{
							APIResources: []metav1.APIResource{
								{
									Kind: "hello-world",
								},
								{
									Namespaced: true,
									Name:       "issuers",
									Kind:       "MyClusterIssuer",
								},
							},
						}, nil
					})
			},
			expSigner: &signerResource{
				name:             "issuers",
				group:            "example.io",
				namespaced:       true,
				signerName:       "my-issuer",
				requestNamespace: "test-ns",
			},
			expOK:  true,
			expErr: false,
		},
		"if external group is registered, and server resources kind exists and cluster scoped, return cluster scoped signer": {
			request: &internalcmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
				},
				Spec: internalcmapi.CertificateRequestSpec{
					IssuerRef: internalcmmeta.ObjectReference{
						Group: "example.io",
						Kind:  "MyIssuer",
						Name:  "my-issuer",
					},
				},
			},

			client: func(t *testing.T) discovery.DiscoveryInterface {
				return discoveryfake.NewDiscovery().
					WithServerGroups(func() (*metav1.APIGroupList, error) {
						return &metav1.APIGroupList{
							Groups: []metav1.APIGroup{
								{Name: "foo"},
								{Name: "bar"},
								{Name: "example.io", Versions: []metav1.GroupVersionForDiscovery{
									{GroupVersion: "foo-bar"},
									{GroupVersion: "bar-foo"},
								}},
							},
						}, nil
					}).
					WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
						if groupVersion != "foo-bar" && groupVersion != "bar-foo" {
							t.Errorf("unexpected group version string: %s", groupVersion)
						}
						return &metav1.APIResourceList{
							APIResources: []metav1.APIResource{
								{
									Kind: "hello-world",
								},
								{
									Namespaced: false,
									Name:       "issuers",
									Kind:       "MyIssuer",
								},
							},
						}, nil
					})
			},
			expSigner: &signerResource{
				name:             "issuers",
				group:            "example.io",
				namespaced:       false,
				signerName:       "my-issuer",
				requestNamespace: "test-ns",
			},
			expOK:  true,
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			a := &approval{
				discoverclient: test.client(t),
			}

			signer, ok, err := a.signerResource(test.request)
			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v",
					test.expErr, err)
			}

			if ok != test.expOK {
				t.Errorf("unexpected ok, exp=%t got=%v",
					test.expOK, ok)
			}

			if !reflect.DeepEqual(signer, test.expSigner) {
				t.Errorf("unexpected signer, exp=%#+v got=%#+v",
					test.expSigner, signer)
			}
		})
	}
}

func TestSignerResourceNames(t *testing.T) {
	tests := map[string]struct {
		signer   *signerResource
		expNames []string
	}{
		"if namespaced, should return a wildcard and namespaced signer name": {
			signer: &signerResource{
				name:             "exampleissuers",
				group:            "my-group.io",
				namespaced:       true,
				signerName:       "my-issuer",
				requestNamespace: "test-ns",
			},
			expNames: []string{
				"exampleissuers.my-group.io/*",
				"exampleissuers.my-group.io/test-ns.my-issuer",
			},
		},
		"if cluster scoped, should return a wildcard and non namespaced signer name": {
			signer: &signerResource{
				name:             "exampleissuers",
				group:            "my-group.io",
				namespaced:       false,
				signerName:       "my-issuer",
				requestNamespace: "test-ns",
			},
			expNames: []string{
				"exampleissuers.my-group.io/*",
				"exampleissuers.my-group.io/my-issuer",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			names := new(approval).signerResourceNames(test.signer)
			if !reflect.DeepEqual(names, test.expNames) {
				t.Errorf("unexpected signer names, exp=%v got=%v",
					test.expNames, names)
			}
		})
	}
}
