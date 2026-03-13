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
package cainjector

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCertFromSecretToInjectableMapFuncBuilder_IgnoresNamespaces(t *testing.T) {
	ignoreNamespaces := map[string]struct{}{"ignored-ns": {}}
	cl := fake.NewClientBuilder().Build()
	log := logr.Discard()
	setup := setup{resourceName: "test"}

	mapFunc := certFromSecretToInjectableMapFuncBuilder(cl, log, setup, ignoreNamespaces)

	secret := &metav1.PartialObjectMetadata{}
	secret.SetNamespace("ignored-ns")
	secret.SetName("my-secret")

	reqs := mapFunc(context.Background(), secret)
	if reqs != nil {
		t.Errorf("Expected nil for ignored namespace, got: %v", reqs)
	}
}
