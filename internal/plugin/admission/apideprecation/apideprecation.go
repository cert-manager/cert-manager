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

package apideprecation

import (
	"context"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cert-manager/cert-manager/pkg/apis/acme"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
)

const PluginName = "APIDeprecation"

type apiDeprecation struct{}

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func() (admission.Interface, error) {
		return NewPlugin(), nil
	})
}

var _ admission.ValidationInterface = &apiDeprecation{}

func (p apiDeprecation) Handles(_ admissionv1.Operation) bool {
	return true
}

func (p apiDeprecation) Validate(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (warnings []string, err error) {
	// Only generate warning messages for cert-manager.io and acme.cert-manager.io APIs
	if request.RequestResource.Group != certmanager.GroupName &&
		request.RequestResource.Group != acme.GroupName {
		return nil, nil
	}

	// All non-v1 API resources in cert-manager.io and acme.cert-manager.io are now deprecated
	if request.RequestResource.Version == "v1" {
		return nil, nil
	}
	return []string{fmt.Sprintf("%s.%s/%s is deprecated in v1.4+, unavailable in v1.6+; use %s.%s/v1", request.RequestResource.Resource, request.RequestResource.Group, request.RequestResource.Version, request.RequestResource.Resource, request.RequestResource.Group)}, nil
}

func NewPlugin() admission.Interface {
	return new(apiDeprecation)
}
