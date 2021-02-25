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

	"github.com/cert-manager/cert-manager/pkg/internal/api/validation"
	"github.com/cert-manager/cert-manager/pkg/internal/apis/acme"
	cmapi "github.com/cert-manager/cert-manager/pkg/internal/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/internal/apis/acme/v1alpha2"
	"github.com/cert-manager/cert-manager/pkg/internal/apis/acme/v1alpha3"
	"github.com/cert-manager/cert-manager/pkg/internal/apis/acme/v1beta1"
	acmevalidation "github.com/cert-manager/cert-manager/pkg/internal/apis/acme/validation"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/internal/apis/meta/v1"
)

// Install registers the API group and adds types to a scheme
func Install(scheme *runtime.Scheme) {
	utilruntime.Must(acme.AddToScheme(scheme))
	utilruntime.Must(v1alpha2.AddToScheme(scheme))
	utilruntime.Must(v1alpha3.AddToScheme(scheme))
	utilruntime.Must(v1beta1.AddToScheme(scheme))
	utilruntime.Must(cmapi.AddToScheme(scheme))
	utilruntime.Must(cmmetav1.AddToScheme(scheme))
}

// InstallValidation registers validation functions for the API group with a
// validation registry
func InstallValidation(registry *validation.Registry) {
	utilruntime.Must(acmevalidation.AddToValidationRegistry(registry))
}
