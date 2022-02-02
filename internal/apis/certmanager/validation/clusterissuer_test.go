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
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmapi "github.com/cert-manager/cert-manager/internal/apis/certmanager"
)

func TestValidateClusterIssuer(t *testing.T) {
	scenarios := map[string]struct {
		cfg       *cmapi.ClusterIssuer
		a         *admissionv1.AdmissionRequest
		expectedE []*field.Error
		expectedW []string
	}{}

	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			gotE, gotW := ValidateClusterIssuer(s.a, s.cfg)
			if len(gotE) != len(s.expectedE) {
				t.Fatalf("Expected errors %v but got %v", s.expectedE, gotE)
			}
			if len(gotW) != len(s.expectedW) {
				t.Fatalf("Expected warnings %v but got %v", s.expectedE, gotE)
			}
			for i, e := range gotE {
				expectedErr := s.expectedE[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected warnings %v but got %v", expectedErr, e)
				}
			}
			for i, w := range gotW {
				expectedWarning := s.expectedW[i]
				if w != expectedWarning {
					t.Errorf("Expected warning %q but got %q", expectedWarning, w)
				}
			}
		})
	}
}

func TestUpdateValidateClusterIssuer(t *testing.T) {
	baseIssuerConfig := cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			SelfSigned: &cmapi.SelfSignedIssuer{},
		}}
	baseIssuer := cmapi.ClusterIssuer{
		Spec: baseIssuerConfig,
	}
	scenarios := map[string]struct {
		iss       *cmapi.ClusterIssuer
		a         *admissionv1.AdmissionRequest
		expectedE []*field.Error
		expectedW []string
	}{}

	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			gotE, gotW := ValidateUpdateClusterIssuer(s.a, &baseIssuer, s.iss)
			if len(gotE) != len(s.expectedE) {
				t.Fatalf("Expected errors %v but got %v", s.expectedE, gotE)
			}
			if len(gotW) != len(s.expectedW) {
				t.Fatalf("Expected warnings %v but got %v", s.expectedE, gotE)
			}
			for i, e := range gotE {
				expectedErr := s.expectedE[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected warnings %v but got %v", expectedErr, e)
				}
			}
			for i, w := range gotW {
				expectedWarning := s.expectedW[i]
				if w != expectedWarning {
					t.Errorf("Expected warning %q but got %q", expectedWarning, w)
				}
			}
		})
	}
}
