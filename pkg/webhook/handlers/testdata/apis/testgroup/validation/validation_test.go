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

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup"
	v1 "github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v1"
)

func TestValidateTestType(t *testing.T) {
	scenarios := map[string]struct {
		obj  *testgroup.TestType
		errs []*field.Error
	}{
		"does not allow testField to be TestFieldValueNotAllowed": {
			obj: &testgroup.TestType{
				TestField: v1.TestFieldValueNotAllowed,
			},
			errs: []*field.Error{
				field.Invalid(field.NewPath("testField"), v1.TestFieldValueNotAllowed, "invalid value"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateTestType(s.obj)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}

func TestValidateTestTypeUpdate(t *testing.T) {
	testImmutableTestTypeField(t, field.NewPath("testFieldImmutable"), func(obj *testgroup.TestType, s testValue) {
		obj.TestFieldImmutable = string(s)
	})

	scenarios := map[string]struct {
		old, new *testgroup.TestType
		errs     []*field.Error
	}{
		"allows all updates if old is nil": {
			new: &testgroup.TestType{
				TestFieldImmutable: "abc",
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateTestTypeUpdate(s.old, s.new)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}

type testValue string

const (
	testValueNone      = ""
	testValueOptionOne = "one"
	testValueOptionTwo = "two"
)

// testImmutableOrderField will test that the field at path fldPath does
// not allow changes after being set, but does allow changes if the old field
// is not set.
func testImmutableTestTypeField(t *testing.T, fldPath *field.Path, setter func(*testgroup.TestType, testValue)) {
	t.Run("should reject updates to "+fldPath.String(), func(t *testing.T) {
		expectedErrs := []*field.Error{
			field.Forbidden(fldPath, "field is immutable once set"),
		}
		old := &testgroup.TestType{}
		new := &testgroup.TestType{}
		setter(old, testValueOptionOne)
		setter(new, testValueOptionTwo)
		errs := ValidateTestTypeUpdate(old, new)
		if len(errs) != len(expectedErrs) {
			t.Errorf("Expected %v but got %v", expectedErrs, errs)
			return
		}
		for i, e := range errs {
			expectedErr := expectedErrs[i]
			if !reflect.DeepEqual(e, expectedErr) {
				t.Errorf("Expected %v but got %v", expectedErr, e)
			}
		}
	})
	t.Run("should allow updates to "+fldPath.String()+" if not already set", func(t *testing.T) {
		expectedErrs := []*field.Error{}
		old := &testgroup.TestType{}
		new := &testgroup.TestType{}
		setter(old, testValueNone)
		setter(new, testValueOptionOne)
		errs := ValidateTestTypeUpdate(old, new)
		if len(errs) != len(expectedErrs) {
			t.Errorf("Expected %v but got %v", expectedErrs, errs)
			return
		}
		for i, e := range errs {
			expectedErr := expectedErrs[i]
			if !reflect.DeepEqual(e, expectedErr) {
				t.Errorf("Expected %v but got %v", expectedErr, e)
			}
		}
	})
}
