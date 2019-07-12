/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package selectors

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Selector interface {
	// Matches returns the number of matches that this selector
	// has with the given object metadata and dnsName.
	// The greater the returned number, the more 'specific' of a
	// match this meta/dnsName pair has with this selector.
	// In some cases, the selector may 'match' (i.e. the bool == true),
	// but the number of matches may be zero (i.e. for a label selector,
	// where an empty selector matches all).
	Matches(meta metav1.ObjectMeta, dnsName string) (bool, int)
}
