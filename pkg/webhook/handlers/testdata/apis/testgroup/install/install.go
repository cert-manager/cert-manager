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
	"github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup"
	v1 "github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v1"
	v2 "github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v2"
	testval "github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/validation"
)

// Install registers the API group and adds types to a scheme
func Install(scheme *runtime.Scheme) {
	utilruntime.Must(testgroup.AddToScheme(scheme))
	utilruntime.Must(v1.AddToScheme(scheme))
	utilruntime.Must(v2.AddToScheme(scheme))
}

func InstallValidations(registry *validation.Registry) {
	utilruntime.Must(testval.Register(registry))
	utilruntime.Must(v2.RegisterValidations(registry))
}
