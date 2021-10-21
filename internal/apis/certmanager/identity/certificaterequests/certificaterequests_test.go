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

package certificaterequests

import (
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/jetstack/cert-manager/pkg/internal/api/validation"
	cmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
)

func TestValidateCreate(t *testing.T) {
	fldPath := field.NewPath("spec")

	tests := map[string]struct {
		req   *admissionv1.AdmissionRequest
		cr    *cmapi.CertificateRequest
		wantE field.ErrorList
		wantW validation.WarningList
	}{
		"if identity fields don't match that of requester, should fail": {
			req: &admissionv1.AdmissionRequest{
				UserInfo: authenticationv1.UserInfo{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string]authenticationv1.ExtraValue{
						"1": []string{"abc", "efg"},
						"2": []string{"efg", "abc"},
					},
				},
			},
			cr: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					UID:      "efg",
					Username: "user-2",
					Groups:   []string{"group-3", "group-4"},
					Extra: map[string][]string{
						"1": {"123", "456"},
						"2": {"efg", "abc"},
					},
				},
			},
			wantE: field.ErrorList{
				field.Forbidden(fldPath.Child("uid"), "uid identity must be that of the requester"),
				field.Forbidden(fldPath.Child("username"), "username identity must be that of the requester"),
				field.Forbidden(fldPath.Child("groups"), "groups identity must be that of the requester"),
				field.Forbidden(fldPath.Child("extra"), "extra identity must be that of the requester"),
			},
		},
		"if identity fields match that of requester, should pass": {
			req: &admissionv1.AdmissionRequest{
				UserInfo: authenticationv1.UserInfo{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string]authenticationv1.ExtraValue{
						"1": []string{"abc", "efg"},
						"2": []string{"efg", "abc"},
					},
				},
			},
			cr: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string][]string{
						"1": {"abc", "efg"},
						"2": {"efg", "abc"},
					},
				},
			},
			wantE: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotE, gotW := ValidateCreate(test.req, test.cr)
			if !reflect.DeepEqual(gotE, test.wantE) {
				t.Errorf("errors from ValidateCreate() = %v, want %v", gotE, test.wantE)
			}
			if !reflect.DeepEqual(gotW, test.wantW) {
				t.Errorf("warnings from ValidateCreate() = %v, want %v", gotW, test.wantW)
			}
		})
	}
}

func TestValidateUpdate(t *testing.T) {
	fldPath := field.NewPath("spec")

	tests := map[string]struct {
		oldCR, newCR *cmapi.CertificateRequest
		wantE        field.ErrorList
		wantW        validation.WarningList
	}{
		"if identity fields don't match that of the old CertificateRequest, should fail": {
			oldCR: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string][]string{
						"1": {"abc", "efg"},
						"2": {"efg", "abc"},
					},
				},
			},
			newCR: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					UID:      "efg",
					Username: "user-2",
					Groups:   []string{"group-3", "group-4"},
					Extra: map[string][]string{
						"1": {"123", "456"},
						"2": {"efg", "abc"},
					},
				},
			},
			wantE: field.ErrorList{
				field.Forbidden(fldPath.Child("uid"), "uid identity cannot be changed once set"),
				field.Forbidden(fldPath.Child("username"), "username identity cannot be changed once set"),
				field.Forbidden(fldPath.Child("groups"), "groups identity cannot be changed once set"),
				field.Forbidden(fldPath.Child("extra"), "extra identity cannot be changed once set"),
			},
		},
		"if identity fields match that of requester, should pass": {
			oldCR: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string][]string{
						"1": {"abc", "efg"},
						"2": {"efg", "abc"},
					},
				},
			},
			newCR: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string][]string{
						"1": {"abc", "efg"},
						"2": {"efg", "abc"},
					},
				},
			},
			wantE: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotE, gotW := ValidateUpdate(nil, test.newCR, test.oldCR)
			if !reflect.DeepEqual(gotE, test.wantE) {
				t.Errorf("errors from ValidateUpdate() = %v, want %v", gotE, test.wantE)
			}
			if !reflect.DeepEqual(gotW, test.wantW) {
				t.Errorf("warnings from ValidateUpdate() = %v, want %v", gotW, test.wantW)
			}
		})
	}
}

func TestMutateCreate(t *testing.T) {
	tests := map[string]struct {
		req                    *admissionv1.AdmissionRequest
		existingCR, expectedCR *cmapi.CertificateRequest
	}{
		"should set the identity of CertificateRequest to that of the requester": {
			req: &admissionv1.AdmissionRequest{
				UserInfo: authenticationv1.UserInfo{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string]authenticationv1.ExtraValue{
						"1": []string{"abc", "efg"},
						"2": []string{"efg", "abc"},
					},
				},
			},
			existingCR: new(cmapi.CertificateRequest),
			expectedCR: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string][]string{
						"1": {"abc", "efg"},
						"2": {"efg", "abc"},
					},
				},
			},
		},
		"should overrite existing user info fields if they exist on a CREATE operation": {
			req: &admissionv1.AdmissionRequest{
				UserInfo: authenticationv1.UserInfo{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string]authenticationv1.ExtraValue{
						"1": []string{"abc", "efg"},
						"2": []string{"efg", "abc"},
					},
				},
			},
			existingCR: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					UID:      "1234",
					Username: "user-2",
					Groups:   []string{"group-3", "group-4"},
					Extra: map[string][]string{
						"3": {"abc", "efg"},
						"4": {"efg", "abc"},
					},
				},
			},
			expectedCR: &cmapi.CertificateRequest{
				Spec: cmapi.CertificateRequestSpec{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string][]string{
						"1": {"abc", "efg"},
						"2": {"efg", "abc"},
					},
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cr := test.expectedCR.DeepCopy()
			MutateCreate(test.req, cr)
			if !reflect.DeepEqual(test.expectedCR, cr) {
				t.Errorf("MutateCreate() = %v, want %v", cr, test.expectedCR)
			}
		})
	}
}
