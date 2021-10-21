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

package mutation_test

import (
	"bytes"
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/internal/api/mutation"
	cminternal "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/webhook"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

var (
	// use the webhook's Scheme during test fixtures as it has all internal and
	// external cert-manager kinds registered
	scheme = webhook.Scheme
)

func TestMutate(t *testing.T) {
	crGVK := &metav1.GroupVersionKind{
		Group:   certmanager.GroupName,
		Version: "v1",
		Kind:    "CertificateRequest",
	}

	testCR := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestTypeMeta(metav1.TypeMeta{
			Kind:       "CertificateRequest",
			APIVersion: "cert-manager.io/v1",
		}),
	)
	testCRBytes, err := json.Marshal(testCR)
	if err != nil {
		t.Fatal(err)
	}

	testNotRegistered := gen.CertificateRequest("test-cr",
		gen.SetCertificateRequestTypeMeta(metav1.TypeMeta{
			Kind:       "NotRegistered",
			APIVersion: "not-registered.io/v1",
		}),
	)
	testNotRegisteredBytes, err := json.Marshal(testNotRegistered)
	if err != nil {
		t.Fatal(err)
	}

	type mutationsEntry struct {
		obj runtime.Object
		fn  func(t *testing.T) mutation.MutateFunc
	}
	type mutationUpdatesEntry struct {
		obj runtime.Object
		fn  func(t *testing.T) mutation.MutateUpdateFunc
	}
	tests := map[string]struct {
		mutations       []mutationsEntry
		mutationUpdates []mutationUpdatesEntry
		req             *admissionv1.AdmissionRequest

		expErr   bool
		expPatch []byte
	}{
		"exit early if operation is not UPDATE or CREATE": {
			mutations:       nil,
			mutationUpdates: nil,
			req: &admissionv1.AdmissionRequest{
				RequestKind: crGVK.DeepCopy(),
				Operation:   admissionv1.Delete,
				Object: runtime.RawExtension{
					Raw: testCRBytes,
				},
			},
			expErr:   false,
			expPatch: nil,
		},
		"if no functions registered, expect only default patch on CREATE": {
			mutations:       nil,
			mutationUpdates: nil,
			req: &admissionv1.AdmissionRequest{
				RequestKind: crGVK.DeepCopy(),
				Operation:   admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: testCRBytes,
				},
			},
			expErr:   false,
			expPatch: []byte("[]"),
		},
		"if no functions registered, expect only default patch on UPDATE": {
			mutations:       nil,
			mutationUpdates: nil,
			req: &admissionv1.AdmissionRequest{
				RequestKind: crGVK.DeepCopy(),
				Operation:   admissionv1.Update,
				OldObject: runtime.RawExtension{
					Raw: testCRBytes,
				},
				Object: runtime.RawExtension{
					Raw: testCRBytes,
				},
			},
			expErr:   false,
			expPatch: []byte("[]"),
		},
		"if kind presented for mutation hasn't been registered for CREATE, error": {
			mutations:       nil,
			mutationUpdates: nil,
			req: &admissionv1.AdmissionRequest{
				RequestKind: crGVK.DeepCopy(),
				Operation:   admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: testNotRegisteredBytes,
				},
			},
			expErr:   true,
			expPatch: nil,
		},
		"if kind presented for mutation hasn't been registered for UPDATE, error": {
			mutations:       nil,
			mutationUpdates: nil,
			req: &admissionv1.AdmissionRequest{
				RequestKind: crGVK.DeepCopy(),
				Operation:   admissionv1.Update,
				OldObject: runtime.RawExtension{
					Raw: testNotRegisteredBytes,
				},
				Object: runtime.RawExtension{
					Raw: testNotRegisteredBytes,
				},
			},
			expErr:   true,
			expPatch: nil,
		},
		"if update mutation function registered for different kind, ignore": {
			mutations: []mutationsEntry{
				{
					obj: new(cminternal.Certificate),
					fn: func(t *testing.T) mutation.MutateFunc {
						return func(_ *admissionv1.AdmissionRequest, _ runtime.Object) {
							t.Error("unexpected call")
						}
					},
				},
			},
			mutationUpdates: nil,
			req: &admissionv1.AdmissionRequest{
				RequestKind: crGVK.DeepCopy(),
				Operation:   admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: testCRBytes,
				},
			},
			expErr:   false,
			expPatch: []byte("[]"),
		},
		"if create mutation function registered for different kind, ignore": {
			mutations: nil,
			mutationUpdates: []mutationUpdatesEntry{
				{
					obj: new(cminternal.Certificate),
					fn: func(t *testing.T) mutation.MutateUpdateFunc {
						return func(_ *admissionv1.AdmissionRequest, _, _ runtime.Object) {
							t.Error("unexpected call")
						}
					},
				},
			},
			req: &admissionv1.AdmissionRequest{
				RequestKind: crGVK.DeepCopy(),
				Operation:   admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: testCRBytes,
				},
			},
			expErr:   false,
			expPatch: []byte("[]"),
		},
		"if create mutation function registered for kind, run mutation": {
			mutations: []mutationsEntry{
				{
					obj: new(cminternal.CertificateRequest),
					fn: func(t *testing.T) mutation.MutateFunc {
						return func(_ *admissionv1.AdmissionRequest, obj runtime.Object) {
							cr := obj.(*cminternal.CertificateRequest)
							cr.Spec.Request = []byte("mutation called")
						}
					},
				},
			},
			mutationUpdates: []mutationUpdatesEntry{
				{
					obj: new(cminternal.Certificate),
					fn: func(t *testing.T) mutation.MutateUpdateFunc {
						return func(_ *admissionv1.AdmissionRequest, _, _ runtime.Object) {
							t.Error("unexpected call")
						}
					},
				},
			},
			req: &admissionv1.AdmissionRequest{
				RequestKind: crGVK.DeepCopy(),
				Operation:   admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: testCRBytes,
				},
			},
			expErr:   false,
			expPatch: []byte(`[{"op":"replace","path":"/spec/request","value":"bXV0YXRpb24gY2FsbGVk"}]`),
		},
		"if update mutation function registered for kind, run mutation": {
			mutations: []mutationsEntry{
				{
					obj: new(cminternal.Certificate),
					fn: func(t *testing.T) mutation.MutateFunc {
						return func(_ *admissionv1.AdmissionRequest, _ runtime.Object) {
							t.Error("unexpected call")
						}
					},
				},
			},
			mutationUpdates: []mutationUpdatesEntry{
				{
					obj: new(cminternal.CertificateRequest),
					fn: func(t *testing.T) mutation.MutateUpdateFunc {
						return func(_ *admissionv1.AdmissionRequest, _, obj runtime.Object) {
							cr := obj.(*cminternal.CertificateRequest)
							cr.Spec.Request = []byte("mutation called")
						}
					},
				},
			},
			req: &admissionv1.AdmissionRequest{
				RequestKind: crGVK.DeepCopy(),
				Operation:   admissionv1.Update,
				Object: runtime.RawExtension{
					Raw: testCRBytes,
				},
				OldObject: runtime.RawExtension{
					Raw: testCRBytes,
				},
			},
			expErr:   false,
			expPatch: []byte(`[{"op":"replace","path":"/spec/request","value":"bXV0YXRpb24gY2FsbGVk"}]`),
		},
		"if multiple create mutation functions registered for kind, run mutation": {
			mutations: []mutationsEntry{
				{
					obj: new(cminternal.CertificateRequest),
					fn: func(t *testing.T) mutation.MutateFunc {
						return func(_ *admissionv1.AdmissionRequest, obj runtime.Object) {
							cr := obj.(*cminternal.CertificateRequest)
							cr.Spec.Request = []byte("mutation called")
						}
					},
				},
				{
					obj: new(cminternal.CertificateRequest),
					fn: func(t *testing.T) mutation.MutateFunc {
						return func(_ *admissionv1.AdmissionRequest, obj runtime.Object) {
							cr := obj.(*cminternal.CertificateRequest)
							if cr.Annotations == nil {
								cr.Annotations = make(map[string]string)
							}
							cr.Annotations["second-mutation"] = "called"
						}
					},
				},
			},
			mutationUpdates: []mutationUpdatesEntry{
				{
					obj: new(cminternal.Certificate),
					fn: func(t *testing.T) mutation.MutateUpdateFunc {
						return func(_ *admissionv1.AdmissionRequest, _, _ runtime.Object) {
							t.Error("unexpected call")
						}
					},
				},
			},
			req: &admissionv1.AdmissionRequest{
				RequestKind: crGVK.DeepCopy(),
				Operation:   admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: testCRBytes,
				},
			},
			expErr:   false,
			expPatch: []byte(`[{"op":"add","path":"/metadata/annotations","value":{"second-mutation":"called"}},{"op":"replace","path":"/spec/request","value":"bXV0YXRpb24gY2FsbGVk"}]`),
		},
		"if multiple update mutation function registered for kind, run mutation": {
			mutations: []mutationsEntry{
				{
					obj: new(cminternal.Certificate),
					fn: func(t *testing.T) mutation.MutateFunc {
						return func(_ *admissionv1.AdmissionRequest, _ runtime.Object) {
							t.Error("unexpected call")
						}
					},
				},
			},
			mutationUpdates: []mutationUpdatesEntry{
				{
					obj: new(cminternal.CertificateRequest),
					fn: func(t *testing.T) mutation.MutateUpdateFunc {
						return func(_ *admissionv1.AdmissionRequest, _, obj runtime.Object) {
							cr := obj.(*cminternal.CertificateRequest)
							cr.Spec.Request = []byte("mutation called")
						}
					},
				},
				{
					obj: new(cminternal.CertificateRequest),
					fn: func(t *testing.T) mutation.MutateUpdateFunc {
						return func(_ *admissionv1.AdmissionRequest, _, obj runtime.Object) {
							cr := obj.(*cminternal.CertificateRequest)
							if cr.Annotations == nil {
								cr.Annotations = make(map[string]string)
							}
							cr.Annotations["second-mutation"] = "called"
						}
					},
				},
			},
			req: &admissionv1.AdmissionRequest{
				RequestKind: crGVK.DeepCopy(),
				Operation:   admissionv1.Update,
				Object: runtime.RawExtension{
					Raw: testCRBytes,
				},
				OldObject: runtime.RawExtension{
					Raw: testCRBytes,
				},
			},
			expErr:   false,
			expPatch: []byte(`[{"op":"add","path":"/metadata/annotations","value":{"second-mutation":"called"}},{"op":"replace","path":"/spec/request","value":"bXV0YXRpb24gY2FsbGVk"}]`),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			reg := mutation.NewRegistry(scheme)

			// Add mutation functions to registry
			for _, m := range test.mutations {
				if err := reg.AddMutateFunc(m.obj, m.fn(t)); err != nil {
					t.Errorf("reg.AddMutateFunc failed %v", err)
				}
			}
			for _, m := range test.mutationUpdates {
				if err := reg.AddMutateUpdateFunc(m.obj, m.fn(t)); err != nil {
					t.Errorf("reg.AddMutateUpdateFunc failed: %v", err)
				}
			}

			patch, err := reg.Mutate(test.req)
			if test.expErr != (err != nil) {
				t.Errorf("unexpected error, exp=%t got=%v",
					test.expErr, err)
			}

			if !bytes.Equal(test.expPatch, patch) {
				t.Errorf("unexpected patch, exp=%s got=%s",
					test.expPatch, patch)
			}
		})
	}
}
