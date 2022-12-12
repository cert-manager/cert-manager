/*
Copyright 2022 The cert-manager Authors.

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

package values

import (
	corev1 "k8s.io/api/core/v1"
)

type Image struct {
	// Image repository
	Repository string `json:"repository"`

	// You can manage a registry with
	// Example:
	//  registry: quay.io
	//  repository: jetstack/cert-manager-controller
	Registry string `json:"registry,omitempty"`

	// Image tag
	Tag string `json:"tag,omitempty"`

	// Setting a digest will override any tag
	Digest string `json:"digest,omitempty"`

	// Image pull policy
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`
}
