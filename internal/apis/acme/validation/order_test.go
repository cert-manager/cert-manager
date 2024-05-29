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
	"k8s.io/utils/ptr"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
)

type testValue string

const (
	testValueNone      = ""
	testValueOptionOne = "one"
	testValueOptionTwo = "two"
)

var (
	someAdmissionRequest = &admissionv1.AdmissionRequest{
		RequestKind: &metav1.GroupVersionKind{
			Group:   "test",
			Kind:    "test",
			Version: "test",
		},
	}
)

// testImmutableOrderField will test that the field at path fldPath does
// not allow changes after being set, but does allow changes if the old field
// is not set.
func testImmutableOrderField(t *testing.T, fldPath *field.Path, setter func(*cmacme.Order, testValue)) {
	t.Run("should reject updates to "+fldPath.String(), func(t *testing.T) {
		expectedErrs := []*field.Error{
			field.Forbidden(fldPath, "field is immutable once set"),
		}
		var expectedWarnings []string
		oldOrder := &cmacme.Order{}
		newOrder := &cmacme.Order{}
		setter(oldOrder, testValueOptionOne)
		setter(newOrder, testValueOptionTwo)
		errs, warnings := ValidateOrderUpdate(someAdmissionRequest, oldOrder, newOrder)
		if len(errs) != len(expectedErrs) {
			t.Errorf("Expected errors %v but got %v", expectedErrs, errs)
			return
		}
		for i, e := range errs {
			expectedErr := expectedErrs[i]
			if !reflect.DeepEqual(e, expectedErr) {
				t.Errorf("Expected error %v but got %v", expectedErr, e)
			}
		}
		if !reflect.DeepEqual(warnings, expectedWarnings) {
			t.Errorf("Expected warnings %+#v but got %+#v", expectedWarnings, warnings)
		}
	})
	t.Run("should allow updates to "+fldPath.String()+" if not already set", func(t *testing.T) {
		expectedErrs := []*field.Error{}
		var expectedWarnings []string
		oldOrder := &cmacme.Order{}
		newOrder := &cmacme.Order{}
		setter(oldOrder, testValueNone)
		setter(newOrder, testValueOptionOne)
		errs, warnings := ValidateOrderUpdate(someAdmissionRequest, oldOrder, newOrder)
		if len(errs) != len(expectedErrs) {
			t.Errorf("Expected errors %v but got %v", expectedErrs, errs)
			return
		}
		for i, e := range errs {
			expectedErr := expectedErrs[i]
			if !reflect.DeepEqual(e, expectedErr) {
				t.Errorf("Expected error %v but got %v", expectedErr, e)
			}
		}
		if !reflect.DeepEqual(warnings, expectedWarnings) {
			t.Errorf("Expected warnings %+#v but got %+#v", expectedWarnings, warnings)
		}
	})
}

func TestValidateOrderUpdate(t *testing.T) {
	authorizationsFldPath := field.NewPath("status", "authorizations")
	challengesFldPath := authorizationsFldPath.Index(0).Child("challenges")

	testImmutableOrderField(t, field.NewPath("spec", "request"), func(o *cmacme.Order, s testValue) {
		if s == testValueNone {
			o.Spec.Request = nil
		}
		o.Spec.Request = []byte(s)
	})
	testImmutableOrderField(t, field.NewPath("status", "url"), func(o *cmacme.Order, s testValue) {
		o.Status.URL = string(s)
	})
	testImmutableOrderField(t, field.NewPath("status", "finalizeURL"), func(o *cmacme.Order, s testValue) {
		o.Status.FinalizeURL = string(s)
	})
	testImmutableOrderField(t, field.NewPath("status", "certificate"), func(o *cmacme.Order, s testValue) {
		if s == testValueNone {
			o.Status.Certificate = nil
		}
		o.Status.Certificate = []byte(s)
	})
	testImmutableOrderField(t, authorizationsFldPath, func(o *cmacme.Order, s testValue) {
		switch s {
		case testValueNone:
			o.Status.Authorizations = []cmacme.ACMEAuthorization{}
		case testValueOptionOne:
			o.Status.Authorizations = []cmacme.ACMEAuthorization{
				{},
			}
		case testValueOptionTwo:
			o.Status.Authorizations = []cmacme.ACMEAuthorization{
				{},
				{},
			}
		}
	})
	testImmutableOrderField(t, authorizationsFldPath.Index(0).Child("url"), func(o *cmacme.Order, s testValue) {
		o.Status.Authorizations = []cmacme.ACMEAuthorization{
			{URL: string(s)},
		}
	})
	testImmutableOrderField(t, authorizationsFldPath.Index(0).Child("identifier"), func(o *cmacme.Order, s testValue) {
		o.Status.Authorizations = []cmacme.ACMEAuthorization{
			{Identifier: string(s)},
		}
	})
	testImmutableOrderField(t, authorizationsFldPath.Index(0).Child("wildcard"), func(o *cmacme.Order, s testValue) {
		switch s {
		case testValueNone:
			o.Status.Authorizations = []cmacme.ACMEAuthorization{
				{Wildcard: nil},
			}
		case testValueOptionOne:
			o.Status.Authorizations = []cmacme.ACMEAuthorization{
				{Wildcard: ptr.To(false)},
			}
		case testValueOptionTwo:
			o.Status.Authorizations = []cmacme.ACMEAuthorization{
				{Wildcard: ptr.To(true)},
			}
		}
	})
	testImmutableOrderField(t, challengesFldPath.Index(0).Child("url"), func(o *cmacme.Order, s testValue) {
		o.Status.Authorizations = []cmacme.ACMEAuthorization{
			{
				Challenges: []cmacme.ACMEChallenge{
					{URL: string(s)},
				},
			},
		}
	})
	testImmutableOrderField(t, challengesFldPath.Index(0).Child("token"), func(o *cmacme.Order, s testValue) {
		o.Status.Authorizations = []cmacme.ACMEAuthorization{
			{
				Challenges: []cmacme.ACMEChallenge{
					{Token: string(s)},
				},
			},
		}
	})
	testImmutableOrderField(t, challengesFldPath.Index(0).Child("type"), func(o *cmacme.Order, s testValue) {
		o.Status.Authorizations = []cmacme.ACMEAuthorization{
			{
				Challenges: []cmacme.ACMEChallenge{
					{Type: string(s)},
				},
			},
		}
	})
	testImmutableOrderField(t, challengesFldPath, func(o *cmacme.Order, s testValue) {
		switch s {
		case testValueNone:
			o.Status.Authorizations = []cmacme.ACMEAuthorization{
				{
					Challenges: []cmacme.ACMEChallenge{},
				},
			}
		case testValueOptionOne:
			o.Status.Authorizations = []cmacme.ACMEAuthorization{
				{
					Challenges: []cmacme.ACMEChallenge{
						{},
					},
				},
			}
		case testValueOptionTwo:
			o.Status.Authorizations = []cmacme.ACMEAuthorization{
				{
					Challenges: []cmacme.ACMEChallenge{
						{},
						{},
					},
				},
			}
		}
	})

	scenarios := map[string]struct {
		old, new *cmacme.Order
		a        *admissionv1.AdmissionRequest
		errs     []*field.Error
		warnings []string
	}{
		"allows all updates if old is nil": {
			new: &cmacme.Order{
				Spec: cmacme.OrderSpec{
					Request: []byte("testing"),
				},
			},
			a: someAdmissionRequest,
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs, warnings := ValidateOrderUpdate(s.a, s.old, s.new)
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

func TestValidateOrder(t *testing.T) {
	scenarios := map[string]struct {
		order    *cmacme.Order
		a        *admissionv1.AdmissionRequest
		errs     []*field.Error
		warnings []string
	}{}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs, warnings := ValidateOrder(s.a, s.order)
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
