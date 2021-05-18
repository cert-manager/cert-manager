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
	"fmt"
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmapiv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmapiv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmapiv1alpha3 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha3"
	cmapiv1beta1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1beta1"
	"github.com/jetstack/cert-manager/pkg/internal/api/validation"
	cmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
)

func TestValidateClusterIssuer(t *testing.T) {
	baseIssuerConfig := cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			SelfSigned: &cmapi.SelfSignedIssuer{},
		}}
	scenarios := map[string]struct {
		cfg       *cmapi.ClusterIssuer
		a         *admissionv1.AdmissionRequest
		expectedE []*field.Error
		expectedW validation.WarningList
	}{
		"v1alpha2 ClusterIssuer created": {
			cfg: &cmapi.ClusterIssuer{
				Spec: baseIssuerConfig,
			},
			a: &admissionv1.AdmissionRequest{
				Kind: metav1.GroupVersionKind{Group: "cert-manager.io",
					Version: "v1alpha2",
					Kind:    "ClusterIssuer"},
			},
			expectedE: []*field.Error{},
			expectedW: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmapiv1alpha2.SchemeGroupVersion.String(),
					"ClusterIssuer",
					cmapiv1.SchemeGroupVersion.String(),
					"ClusterIssuer"),
			},
		},
		"v1alpha3 ClusterIssuer created": {
			cfg: &cmapi.ClusterIssuer{
				Spec: baseIssuerConfig,
			},
			a: &admissionv1.AdmissionRequest{
				Kind: metav1.GroupVersionKind{Group: "cert-manager.io",
					Version: "v1alpha3",
					Kind:    "ClusterIssuer"},
			},
			expectedE: []*field.Error{},
			expectedW: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmapiv1alpha3.SchemeGroupVersion.String(),
					"ClusterIssuer",
					cmapiv1.SchemeGroupVersion.String(),
					"ClusterIssuer"),
			},
		},
		"v1beta1 ClusterIssuer created": {
			cfg: &cmapi.ClusterIssuer{
				Spec: baseIssuerConfig,
			},
			a: &admissionv1.AdmissionRequest{
				Kind: metav1.GroupVersionKind{Group: "cert-manager.io",
					Version: "v1beta1",
					Kind:    "ClusterIssuer"},
			},
			expectedE: []*field.Error{},
			expectedW: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmapiv1beta1.SchemeGroupVersion.String(),
					"ClusterIssuer",
					cmapiv1.SchemeGroupVersion.String(),
					"ClusterIssuer"),
			},
		},
	}

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
		expectedW validation.WarningList
	}{
		"ClusterIssuer updated to v1alpha2 version": {
			iss: &cmapi.ClusterIssuer{
				Spec: baseIssuerConfig,
			},
			a: &admissionv1.AdmissionRequest{
				Kind: metav1.GroupVersionKind{Group: "cert-manager.io",
					Version: "v1alpha2",
					Kind:    "ClusterIssuer"},
			},
			expectedE: []*field.Error{},
			expectedW: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmapiv1alpha2.SchemeGroupVersion.String(),
					"ClusterIssuer",
					cmapiv1.SchemeGroupVersion.String(),
					"ClusterIssuer"),
			},
		},
		"ClusterIssuer updated to v1alpha3 version": {
			iss: &cmapi.ClusterIssuer{
				Spec: baseIssuerConfig,
			},
			a: &admissionv1.AdmissionRequest{
				Kind: metav1.GroupVersionKind{Group: "cert-manager.io",
					Version: "v1alpha3",
					Kind:    "ClusterIssuer"},
			},
			expectedE: []*field.Error{},
			expectedW: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmapiv1alpha3.SchemeGroupVersion.String(),
					"ClusterIssuer",
					cmapiv1.SchemeGroupVersion.String(),
					"ClusterIssuer"),
			},
		},
		"ClusterIssuer updated to v1beta1 version": {
			iss: &cmapi.ClusterIssuer{
				Spec: baseIssuerConfig,
			},
			a: &admissionv1.AdmissionRequest{
				Kind: metav1.GroupVersionKind{Group: "cert-manager.io",
					Version: "v1beta1",
					Kind:    "ClusterIssuer"},
			},
			expectedE: []*field.Error{},
			expectedW: validation.WarningList{
				fmt.Sprintf(deprecationMessageTemplate,
					cmapiv1beta1.SchemeGroupVersion.String(),
					"ClusterIssuer",
					cmapiv1.SchemeGroupVersion.String(),
					"ClusterIssuer"),
			},
		},
	}

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
