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

package conversion

import (
	"context"
	"testing"
	"time"

	logtesting "github.com/go-logr/logr/testing"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/diff"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/cert-manager/pkg/webhook/handlers"
	testapi "github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/install"
	testv1 "github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v1"
	testv2 "github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v2"
	"github.com/cert-manager/cert-manager/test/integration/framework"
)

func TestConversion(t *testing.T) {
	tests := map[string]struct {
		input     client.Object
		targetGVK schema.GroupVersionKind
		output    client.Object
	}{
		"should convert from v1 to v2": {
			input: &testv1.TestType{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				TestFieldPtr: pointer.StringPtr("test1"),
			},
			targetGVK: testv2.SchemeGroupVersion.WithKind("TestType"),
			output: &testv2.TestType{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				TestFieldPtrAlt: pointer.StringPtr("test1"),
			},
		},
		"should convert from v2 to v1": {
			input: &testv2.TestType{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				TestFieldPtrAlt: pointer.StringPtr("test1"),
			},
			targetGVK: testv1.SchemeGroupVersion.WithKind("TestType"),
			output: &testv1.TestType{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				TestFieldPtr: pointer.StringPtr("test1"),
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			log := logtesting.NewTestLogger(t)

			scheme := runtime.NewScheme()
			testapi.Install(scheme)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
			defer cancel()

			config, stop := framework.RunControlPlane(
				t, ctx,
				framework.WithCRDDirectory("../../../pkg/webhook/handlers/testdata/apis/testgroup/crds"),
				framework.WithWebhookConversionHandler(handlers.NewSchemeBackedConverter(log, scheme)),
			)
			defer stop()
			cl, err := client.New(config, client.Options{Scheme: scheme})
			if err != nil {
				t.Fatal(err)
			}

			if err := cl.Create(ctx, test.input); err != nil {
				t.Fatal(err)
			}
			meta := test.input.(metav1.ObjectMetaAccessor)

			convertedObj, err := scheme.New(test.targetGVK)
			if err != nil {
				t.Fatal(err)
			}

			if err := cl.Get(ctx, client.ObjectKey{Name: meta.GetObjectMeta().GetName(), Namespace: meta.GetObjectMeta().GetNamespace()}, convertedObj.(client.Object)); err != nil {
				t.Fatalf("failed to fetch object in expected API version: %v", err)
			}

			convertedObjMeta := convertedObj.(metav1.ObjectMetaAccessor)
			convertedObjMeta.GetObjectMeta().SetCreationTimestamp(metav1.Time{})
			convertedObjMeta.GetObjectMeta().SetGeneration(0)
			convertedObjMeta.GetObjectMeta().SetUID("")
			convertedObjMeta.GetObjectMeta().SetSelfLink("")
			convertedObjMeta.GetObjectMeta().SetResourceVersion("")
			convertedObjMeta.GetObjectMeta().SetManagedFields([]metav1.ManagedFieldsEntry{})

			if !equality.Semantic.DeepEqual(test.output, convertedObj) {
				t.Errorf("unexpected output: %s", diff.ObjectReflectDiff(test.output, convertedObj))
			}
		})
	}
}
