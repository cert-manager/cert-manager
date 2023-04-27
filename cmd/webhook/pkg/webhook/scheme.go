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

package webhook

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// Define a Scheme that has all cert-manager API types registered, including
// the internal API version, defaulting functions and conversion functions for
// all external versions.
// This scheme should *only* be used by the webhook as the conversion/defaulter
// functions are likely to change in the future.

var (
	// Scheme is a Kubernetes runtime.Scheme with all internal and external API
	// versions for cert-manager types registered.
	// TODO: this type should not be exported
	Scheme = runtime.NewScheme()
)
