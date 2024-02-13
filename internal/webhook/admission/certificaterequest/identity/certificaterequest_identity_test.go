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

package identity

import (
	"context"
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
)

var correctRequestResource = &metav1.GroupVersionResource{
	Group:    "cert-manager.io",
	Version:  "v1",
	Resource: "certificaterequests",
}

func TestMutate(t *testing.T) {
	plugin := NewPlugin().(*certificateRequestIdentity)
	cr := &certmanager.CertificateRequest{}
	err := plugin.Mutate(context.Background(), admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		RequestResource: &metav1.GroupVersionResource{
			Group:    "cert-manager.io",
			Version:  "v1",
			Resource: "certificaterequests",
		},
		UserInfo: authenticationv1.UserInfo{
			Username: "testuser",
			UID:      "testuid",
			Groups:   []string{"testgroup"},
			Extra: map[string]authenticationv1.ExtraValue{
				"testkey": []string{"testvalue"},
			},
		}}, cr)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if cr.Spec.Username != "testuser" {
		t.Errorf("unexpected username. got: %q, expected %q", cr.Spec.UID, "testuser")
	}
	if cr.Spec.UID != "testuid" {
		t.Errorf("unexpected uid. got: %q, expected %q", cr.Spec.UID, "testuid")
	}
	if len(cr.Spec.Groups) != 1 || cr.Spec.Groups[0] != "testgroup" {
		t.Errorf("unexpected groups. got: %q, expected %q", cr.Spec.Groups, "[testgroup]")
	}
	if len(cr.Spec.Extra) != 1 || len(cr.Spec.Extra["testkey"]) != 1 || cr.Spec.Extra["testkey"][0] != "testvalue" {
		t.Errorf("unexpected uid. got: %q, expected %q", cr.Spec.Extra, "{testkey=testvalue}")
	}
}

func TestMutate_Ignores(t *testing.T) {
	plugin := NewPlugin().(*certificateRequestIdentity)
	tests := map[string]struct {
		op  admissionv1.Operation
		gvr *metav1.GroupVersionResource
	}{
		"ignores if resource is not 'certificaterequests'": {
			op: admissionv1.Create,
			gvr: &metav1.GroupVersionResource{
				Group:    "cert-manager.io",
				Version:  "v1",
				Resource: "not-certificaterequests",
			},
		},
		"ignores if group is not 'cert-manager.io'": {
			op: admissionv1.Create,
			gvr: &metav1.GroupVersionResource{
				Group:    "not-cert-manager.io",
				Version:  "v1",
				Resource: "certificaterequests",
			},
		},
		"ignores if operation is not Create": {
			op: admissionv1.Update,
			gvr: &metav1.GroupVersionResource{
				Group:    "cert-manager.io",
				Version:  "v1",
				Resource: "certificaterequests",
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cr := &certmanager.CertificateRequest{}
			err := plugin.Mutate(context.Background(), admissionv1.AdmissionRequest{
				Operation:       test.op,
				RequestResource: test.gvr,
				UserInfo: authenticationv1.UserInfo{
					Username: "testuser",
					UID:      "testuid",
					Groups:   []string{"testgroup"},
					Extra: map[string]authenticationv1.ExtraValue{
						"testkey": []string{"testvalue"},
					},
				}}, cr)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if cr.Spec.UID != "" || cr.Spec.Extra != nil || cr.Spec.Username != "" || len(cr.Spec.Groups) != 0 {
				t.Errorf("unexpected mutation")
			}
		})
	}
}

func TestValidateCreate(t *testing.T) {
	fldPath := field.NewPath("spec")

	tests := map[string]struct {
		req   *admissionv1.AdmissionRequest
		cr    *certmanager.CertificateRequest
		wantE error
		wantW []string
	}{
		"if identity fields don't match that of requester, should fail": {
			req: &admissionv1.AdmissionRequest{
				Operation:       admissionv1.Create,
				RequestResource: correctRequestResource,
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
			cr: &certmanager.CertificateRequest{
				Spec: certmanager.CertificateRequestSpec{
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
			}.ToAggregate(),
		},
		"if identity fields match that of requester, should pass": {
			req: &admissionv1.AdmissionRequest{
				Operation:       admissionv1.Create,
				RequestResource: correctRequestResource,
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
			cr: &certmanager.CertificateRequest{
				Spec: certmanager.CertificateRequestSpec{
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
			p := NewPlugin().(*certificateRequestIdentity)
			gotW, gotE := p.Validate(context.Background(), *test.req, nil, test.cr)
			compareErrors(t, test.wantE, gotE)
			if !reflect.DeepEqual(gotW, test.wantW) {
				t.Errorf("warnings from ValidateCreate() = %v, want %v", gotW, test.wantW)
			}
		})
	}
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

func TestValidateUpdate(t *testing.T) {
	fldPath := field.NewPath("spec")

	tests := map[string]struct {
		req          *admissionv1.AdmissionRequest
		oldCR, newCR *certmanager.CertificateRequest
		wantE        error
		wantW        []string
	}{
		"if identity fields don't match that of the old CertificateRequest, should fail": {
			req: &admissionv1.AdmissionRequest{
				Operation:       admissionv1.Update,
				RequestResource: correctRequestResource,
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
			oldCR: &certmanager.CertificateRequest{
				Spec: certmanager.CertificateRequestSpec{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string][]string{
						"1": {"abc", "efg"},
						"2": {"efg", "abc"},
					},
				},
			},
			newCR: &certmanager.CertificateRequest{
				Spec: certmanager.CertificateRequestSpec{
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
			}.ToAggregate(),
		},
		"if identity fields match that of requester, should pass": {
			req: &admissionv1.AdmissionRequest{
				Operation:       admissionv1.Update,
				RequestResource: correctRequestResource,
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
			oldCR: &certmanager.CertificateRequest{
				Spec: certmanager.CertificateRequestSpec{
					UID:      "abc",
					Username: "user-1",
					Groups:   []string{"group-1", "group-2"},
					Extra: map[string][]string{
						"1": {"abc", "efg"},
						"2": {"efg", "abc"},
					},
				},
			},
			newCR: &certmanager.CertificateRequest{
				Spec: certmanager.CertificateRequestSpec{
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
			p := NewPlugin().(*certificateRequestIdentity)
			gotW, gotE := p.Validate(context.Background(), *test.req, test.oldCR, test.newCR)
			compareErrors(t, test.wantE, gotE)
			if !reflect.DeepEqual(gotW, test.wantW) {
				t.Errorf("warnings from ValidateUpdate() = %v, want %v", gotW, test.wantW)
			}
		})
	}
}

func TestMutateCreate(t *testing.T) {
	tests := map[string]struct {
		req                    *admissionv1.AdmissionRequest
		existingCR, expectedCR *certmanager.CertificateRequest
	}{
		"should set the identity of CertificateRequest to that of the requester": {
			req: &admissionv1.AdmissionRequest{
				Operation:       admissionv1.Create,
				RequestResource: correctRequestResource,
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
			existingCR: new(certmanager.CertificateRequest),
			expectedCR: &certmanager.CertificateRequest{
				Spec: certmanager.CertificateRequestSpec{
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
		"should overwrite user info fields if already present during a CREATE operation": {
			req: &admissionv1.AdmissionRequest{
				Operation:       admissionv1.Create,
				RequestResource: correctRequestResource,
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
			existingCR: &certmanager.CertificateRequest{
				Spec: certmanager.CertificateRequestSpec{
					UID:      "1234",
					Username: "user-2",
					Groups:   []string{"group-3", "group-4"},
					Extra: map[string][]string{
						"3": {"abc", "efg"},
						"4": {"efg", "abc"},
					},
				},
			},
			expectedCR: &certmanager.CertificateRequest{
				Spec: certmanager.CertificateRequestSpec{
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
			cr := test.existingCR.DeepCopy()
			p := NewPlugin().(*certificateRequestIdentity)
			if err := p.Mutate(context.Background(), *test.req, cr); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(test.expectedCR, cr) {
				t.Errorf("MutateCreate() = %v, want %v", cr, test.expectedCR)
			}
		})
	}
}

func TestMutateUpdate(t *testing.T) {
	tests := map[string]struct {
		req                    *admissionv1.AdmissionRequest
		existingCR, expectedCR *certmanager.CertificateRequest
	}{
		"should not overwrite user info fields during an Update operation": {
			req: &admissionv1.AdmissionRequest{
				Operation:       admissionv1.Update,
				RequestResource: correctRequestResource,
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
			existingCR: &certmanager.CertificateRequest{
				Spec: certmanager.CertificateRequestSpec{
					UID:      "1234",
					Username: "user-2",
					Groups:   []string{"group-3", "group-4"},
					Extra: map[string][]string{
						"3": {"abc", "efg"},
						"4": {"efg", "abc"},
					},
				},
			},
			expectedCR: &certmanager.CertificateRequest{
				Spec: certmanager.CertificateRequestSpec{
					UID:      "1234",
					Username: "user-2",
					Groups:   []string{"group-3", "group-4"},
					Extra: map[string][]string{
						"3": {"abc", "efg"},
						"4": {"efg", "abc"},
					},
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cr := test.existingCR.DeepCopy()
			p := NewPlugin().(*certificateRequestIdentity)
			if err := p.Mutate(context.Background(), *test.req, cr); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(test.expectedCR, cr) {
				t.Errorf("MutateCreate() = %v, want %v", cr, test.expectedCR)
			}
		})
	}
}
