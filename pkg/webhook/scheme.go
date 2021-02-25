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

package webhook

import (
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cert-manager/cert-manager/pkg/internal/api/validation"
	acmeinstall "github.com/cert-manager/cert-manager/pkg/internal/apis/acme/install"
	cminstall "github.com/cert-manager/cert-manager/pkg/internal/apis/certmanager/install"
	metainstall "github.com/cert-manager/cert-manager/pkg/internal/apis/meta/install"
)

// Define a Scheme that has all cert-manager API types registered, including
// the internal API version, defaulting functions and conversion functions for
// all external versions.
// This scheme should *only* be used by the webhook as the conversion/defaulter
// functions are likely to change in future, and all controllers consuming
// cert-manager APIs should have a consistent view of all API kinds.

var (
	// Scheme is a Kubernetes runtime.Scheme with all internal and external API
	// versions for cert-manager types registered.
	Scheme = runtime.NewScheme()

	// ValidationRegistry is a validation registry with all required
	// validations that should be enforced by the webhook component.
	ValidationRegistry = validation.NewRegistry(Scheme)
)

func init() {
	cminstall.Install(Scheme)
	acmeinstall.Install(Scheme)
	metainstall.Install(Scheme)

	cminstall.InstallValidation(ValidationRegistry)
	acmeinstall.InstallValidation(ValidationRegistry)
}
