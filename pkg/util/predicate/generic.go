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

package predicate

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ResourceOwnedBy will filter returned results to only those with the
// given resource as an owner.
func ResourceOwnedBy(owner runtime.Object) Func {
	return func(obj runtime.Object) bool {
		return metav1.IsControlledBy(obj.(metav1.Object), owner.(metav1.Object))
	}
}

// ResourceOwnerOf will filter returned results to only those that own the given
// resource.
func ResourceOwnerOf(obj runtime.Object) Func {
	return func(ownerObj runtime.Object) bool {
		return metav1.IsControlledBy(obj.(metav1.Object), ownerObj.(metav1.Object))
	}
}
