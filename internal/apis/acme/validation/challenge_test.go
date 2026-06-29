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

package validation

import (
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
)

func TestValidateChallengeUpdate(t *testing.T) {
	someAdmissionRequest := &admissionv1.AdmissionRequest{
		RequestKind: &metav1.GroupVersionKind{
			Group:   "test",
			Kind:    "test",
			Version: "test",
		},
	}

	scenarios := map[string]struct {
		old, new *cmacme.Challenge
		a        *admissionv1.AdmissionRequest
		errs     []*field.Error
		warnings []string
	}{
		"allows setting challenge spec for the first time": {
			new: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			a: someAdmissionRequest,
		},
		"disallow updating challenge spec": {
			old: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			new: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "newtesturl",
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Forbidden(field.NewPath("spec"), "challenge spec is immutable after creation"),
			},
		},
		"allow updating challenge spec if no changes are made": {
			old: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			new: &cmacme.Challenge{
				Spec: cmacme.ChallengeSpec{
					URL: "testurl",
				},
			},
			a: someAdmissionRequest,
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs, warnings := ValidateChallengeUpdate(s.a, s.old, s.new)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected errors %v but got %v", expectedErr, e)
				}
			}
			if !reflect.DeepEqual(warnings, s.warnings) {
				t.Errorf("Expected warnings %+#v but got %+#v", s.warnings, warnings)
			}
		})
	}
}

// TestValidateChallenge verifies that the webhook rejects Challenge resources
// lacking a controller owner reference to an Order. This is defence in depth
// against Challenge smuggling (GHSA-8rvj-mm4h-c258).
func TestValidateChallenge(t *testing.T) {
	someAdmissionRequest := &admissionv1.AdmissionRequest{
		RequestKind: &metav1.GroupVersionKind{
			Group:   "test",
			Kind:    "test",
			Version: "test",
		},
	}

	ownerRefPath := field.NewPath("metadata", "ownerReferences")
	ownerRefDetail := "challenge resources must be owned by an Order resource"

	scenarios := map[string]struct {
		chal     *cmacme.Challenge
		a        *admissionv1.AdmissionRequest
		errs     []*field.Error
		warnings []string
	}{
		"accepts challenge with Order controller owner reference": {
			chal: &cmacme.Challenge{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "acme.cert-manager.io/v1",
							Kind:       "Order",
							Name:       "my-order",
							UID:        "abc-123",
							Controller: new(true),
						},
					},
				},
			},
			a: someAdmissionRequest,
		},
		"rejects challenge with no owner references": {
			chal: &cmacme.Challenge{},
			a:    someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(ownerRefPath, []metav1.OwnerReference(nil), ownerRefDetail),
			},
		},
		"rejects challenge with wrong Kind in owner reference": {
			chal: &cmacme.Challenge{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "acme.cert-manager.io/v1",
							Kind:       "Certificate",
							Name:       "my-cert",
							UID:        "abc-123",
							Controller: new(true),
						},
					},
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(ownerRefPath, []metav1.OwnerReference{
					{APIVersion: "acme.cert-manager.io/v1", Kind: "Certificate", Name: "my-cert", UID: "abc-123", Controller: new(true)},
				}, ownerRefDetail),
			},
		},
		"rejects challenge with owner reference that is not a controller": {
			chal: &cmacme.Challenge{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "acme.cert-manager.io/v1",
							Kind:       "Order",
							Name:       "my-order",
							UID:        "abc-123",
						},
					},
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(ownerRefPath, []metav1.OwnerReference{
					{APIVersion: "acme.cert-manager.io/v1", Kind: "Order", Name: "my-order", UID: "abc-123"},
				}, ownerRefDetail),
			},
		},
		"rejects challenge with owner reference to wrong API group": {
			chal: &cmacme.Challenge{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "cert-manager.io/v1",
							Kind:       "Order",
							Name:       "my-order",
							UID:        "abc-123",
							Controller: new(true),
						},
					},
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(ownerRefPath, []metav1.OwnerReference{
					{APIVersion: "cert-manager.io/v1", Kind: "Order", Name: "my-order", UID: "abc-123", Controller: new(true)},
				}, ownerRefDetail),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs, warnings := ValidateChallenge(s.a, s.chal)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected errors %v but got %v", expectedErr, e)
				}
			}
			if !reflect.DeepEqual(warnings, s.warnings) {
				t.Errorf("Expected warnings %+#v but got %+#v", s.warnings, warnings)
			}
		})
	}
}
