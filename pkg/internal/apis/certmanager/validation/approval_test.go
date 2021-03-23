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
	"errors"
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	cmmeta "github.com/jetstack/cert-manager/pkg/internal/apis/meta"
)

func TestReviewApproval(t *testing.T) {
	issuerRef := cmmeta.ObjectReference{
		Name:  "test-issuer",
		Kind:  "Issuer",
		Group: "example.io",
	}

	tests := map[string]struct {
		oldCR, newCR *cmapi.CertificateRequest
		reaction     func(t *testing.T) clienttesting.ReactionFunc

		expErr field.ErrorList
	}{
		"if approval condition doesn't exist for either, don't review": {
			oldCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{},
				},
			},
			newCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{},
				},
			},
			reaction: func(t *testing.T) clienttesting.ReactionFunc {
				return func(_ clienttesting.Action) (bool, runtime.Object, error) {
					t.Fatal("unexpected review call")
					return true, nil, nil
				}
			},
		},
		"if approval condition is the same for both, don't review": {
			oldCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type: cmapi.CertificateRequestConditionApproved,
						},
					},
				},
			},
			newCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type: cmapi.CertificateRequestConditionApproved,
						},
					},
				},
			},
			reaction: func(t *testing.T) clienttesting.ReactionFunc {
				return func(_ clienttesting.Action) (bool, runtime.Object, error) {
					t.Fatal("unexpected review call")
					return true, nil, nil
				}
			},
		},
		"if denied condition for both, don't review": {
			oldCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type: cmapi.CertificateRequestConditionDenied,
						},
					},
				},
			},
			newCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type: cmapi.CertificateRequestConditionDenied,
						},
					},
				},
			},
			reaction: func(t *testing.T) clienttesting.ReactionFunc {
				return func(_ clienttesting.Action) (bool, runtime.Object, error) {
					t.Fatal("unexpected review call")
					return true, nil, nil
				}
			},
		},
		"if approval condition changes, review returns error, error": {
			oldCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{},
				},
			},
			newCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type: cmapi.CertificateRequestConditionApproved,
						},
					},
				},
			},
			reaction: func(t *testing.T) clienttesting.ReactionFunc {
				return func(_ clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("an error")
				}
			},
			expErr: field.ErrorList{
				field.InternalError(field.NewPath("status.conditions"), errors.New("an error")),
			},
		},
		"if deny condition changes, review returns error, error": {
			oldCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{},
				},
			},
			newCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type: cmapi.CertificateRequestConditionDenied,
						},
					},
				},
			},
			reaction: func(t *testing.T) clienttesting.ReactionFunc {
				return func(_ clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("an error")
				}
			},
			expErr: field.ErrorList{
				field.InternalError(field.NewPath("status.conditions"), errors.New("an error")),
			},
		},
		"if approve condition changes, review returns false, error": {
			oldCR: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					IssuerRef: issuerRef,
				},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{},
				},
			},
			newCR: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					IssuerRef: issuerRef,
				},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type: cmapi.CertificateRequestConditionApproved,
						},
					},
				},
			},
			reaction: func(t *testing.T) clienttesting.ReactionFunc {
				return func(_ clienttesting.Action) (bool, runtime.Object, error) {
					return true, &authzv1.SubjectAccessReview{
						Status: authzv1.SubjectAccessReviewStatus{
							Allowed: false,
						},
					}, nil
				}
			},
			expErr: field.ErrorList{
				field.Forbidden(field.NewPath("status.conditions"),
					`user "user-1" does not have permissions to set approved/denied conditions for issuer {test-issuer Issuer example.io}`),
			},
		},
		"if deny condition changes, review returns false, error": {
			oldCR: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					IssuerRef: issuerRef,
				},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{},
				},
			},
			newCR: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					IssuerRef: issuerRef,
				},
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type: cmapi.CertificateRequestConditionDenied,
						},
					},
				},
			},
			reaction: func(t *testing.T) clienttesting.ReactionFunc {
				return func(_ clienttesting.Action) (bool, runtime.Object, error) {
					return true, &authzv1.SubjectAccessReview{
						Status: authzv1.SubjectAccessReviewStatus{
							Allowed: false,
						},
					}, nil
				}
			},
			expErr: field.ErrorList{
				field.Forbidden(field.NewPath("status.conditions"),
					`user "user-1" does not have permissions to set approved/denied conditions for issuer {test-issuer Issuer example.io}`),
			},
		},
		"if approve condition changes, review returns true, don't error": {
			oldCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{},
				},
			},
			newCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type: cmapi.CertificateRequestConditionApproved,
						},
					},
				},
			},
			reaction: func(t *testing.T) clienttesting.ReactionFunc {
				return func(_ clienttesting.Action) (bool, runtime.Object, error) {
					return true, &authzv1.SubjectAccessReview{
						Status: authzv1.SubjectAccessReviewStatus{
							Allowed: true,
						},
					}, nil
				}
			},
			expErr: nil,
		},
		"if denied condition changes, review returns true, don't error": {
			oldCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{},
				},
			},
			newCR: &cmapi.CertificateRequest{
				Status: cmapi.CertificateRequestStatus{
					Conditions: []cmapi.CertificateRequestCondition{
						{
							Type: cmapi.CertificateRequestConditionDenied,
						},
					},
				},
			},
			reaction: func(t *testing.T) clienttesting.ReactionFunc {
				return func(_ clienttesting.Action) (bool, runtime.Object, error) {
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
			client := fake.NewSimpleClientset()
			client.Fake.PrependReactor("create", "subjectaccessreviews", test.reaction(t))
			sarclient := client.AuthorizationV1().SubjectAccessReviews()

			req := &admissionv1.AdmissionRequest{
				UserInfo: authnv1.UserInfo{
					Username: "user-1",
				},
			}

			err := ReviewApproval(sarclient, req, test.oldCR, test.newCR)
			if !reflect.DeepEqual(err, test.expErr) {
				t.Errorf("unexpected review error, exp=%v got=%v",
					test.expErr, err)
			}
		})
	}
}
