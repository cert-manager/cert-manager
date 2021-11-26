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

// Package install installs the API group, making it available as an option to
// all of the API encoding/decoding machinery.
package install

import (
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/jetstack/cert-manager/internal/api/mutation"
	"github.com/jetstack/cert-manager/internal/api/validation"
	"github.com/jetstack/cert-manager/internal/apis/certmanager"
	cmidentity "github.com/jetstack/cert-manager/internal/apis/certmanager/identity"
	v1 "github.com/jetstack/cert-manager/internal/apis/certmanager/v1"
	cmvalidation "github.com/jetstack/cert-manager/internal/apis/certmanager/validation"
	cmmetav1 "github.com/jetstack/cert-manager/internal/apis/meta/v1"
)

// Install registers the API group and adds types to a scheme
func Install(scheme *runtime.Scheme) {
	utilruntime.Must(certmanager.AddToScheme(scheme))
	// The first version in this list will be the default version used
	utilruntime.Must(v1.AddToScheme(scheme))

	utilruntime.Must(cmmetav1.AddToScheme(scheme))
}

// InstallValidation registers validation functions for the API group with a
// validation registry
func InstallValidation(registry *validation.Registry) {
	utilruntime.Must(cmvalidation.AddToValidationRegistry(registry))
	utilruntime.Must(cmidentity.AddToValidationRegistry(registry))
}

// InstallMutation registers mutation functions for the API group with a
// mutation registry
func InstallMutation(registry *mutation.Registry) {
	utilruntime.Must(cmidentity.AddToMutationRegistry(registry))
}
