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
)

// Func is a generic function used to filter various types of resources.
type Func[T metav1.Object] func(obj T) bool

// Funcs is a list of predicates to be AND'd together.
type Funcs[T metav1.Object] []Func[T]

// Evaluate will evaluate all the predicate functions in order, AND'ing
// together the results.
func (f Funcs[T]) Evaluate(obj T) bool {
	for _, fn := range f {
		if !fn(obj) {
			return false
		}
	}
	return true
}

// An ExtractorFunc applies a transformation to a runtime.Object and creates a
// predicate function based on the result of the transformation.
// This can be used to apply complex lookup logic to determine which resources
// should be enqueued if another resource being watched changes, for example,
// enqueuing all Certificate resources that own a CertificateRequest that has
// been observed, or enqueuing all Certificate resources that specify
// `status.nextPrivateKeySecretName` as the name of the Secret being processed.
// ExtractorFunc builds a predicate.Func for the target type based on the
// provided object (usually the object from a watch event).
type ExtractorFunc[T, U metav1.Object] func(obj U) Func[T]

// ExtractResourceName is a helper function used to extract a name from a
// metav1.Object being enqueued to construct a Func that is variadic
// based on a string value.
func ExtractResourceName[U, T metav1.Object](p func(name string) Func[T]) ExtractorFunc[T, U] {
	return func(obj U) Func[T] {
		return p(obj.GetName())
	}
}
