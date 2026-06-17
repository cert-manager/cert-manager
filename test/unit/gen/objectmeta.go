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

package gen

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// DefaultTestNamespace is the default namespace set on resources that
	// are namespaced.
	DefaultTestNamespace = "default-unit-test-ns"
)

// ObjectMetaModifier applies a transformation to the provider ObjectMeta
type ObjectMetaModifier func(*metav1.ObjectMeta)

// ObjectMeta creates a new metav1.ObjectMeta with the given name, optionally
// applying the provided ObjectMetaModifiers.
// It applies a DefaultTestNamespace by default.
// Cluster-scoped resource generators should explicitly add `SetNamespace("")`
// to their constructors.
func ObjectMeta(name string, mods ...ObjectMetaModifier) metav1.ObjectMeta {
	m := &metav1.ObjectMeta{
		Name:      name,
		Namespace: DefaultTestNamespace,
	}
	for _, mod := range mods {
		mod(m)
	}
	return *m
}
