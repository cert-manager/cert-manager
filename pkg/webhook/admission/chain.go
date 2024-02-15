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

package admission

import (
	"context"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
)

type PluginChain []Interface

var _ Interface = PluginChain(nil)
var _ ValidationInterface = PluginChain(nil)
var _ MutationInterface = PluginChain(nil)

func (pc PluginChain) Handles(operation admissionv1.Operation) bool {
	for _, plugin := range pc {
		if plugin.Handles(operation) {
			return true
		}
	}
	return false
}

func (pc PluginChain) Validate(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) ([]string, error) {
	var allWarnings []string
	var allErrors []error
	for _, handler := range pc {
		if !handler.Handles(request.Operation) {
			continue
		}
		if validator, ok := handler.(ValidationInterface); ok {
			warnings, err := validator.Validate(ctx, request, oldObj, obj)
			allErrors = append(allErrors, err)
			allWarnings = append(allWarnings, warnings...)
		}
	}
	return allWarnings, utilerrors.NewAggregate(allErrors)
}

func (pc PluginChain) Mutate(ctx context.Context, request admissionv1.AdmissionRequest, obj *unstructured.Unstructured) error {
	for _, handler := range pc {
		if !handler.Handles(request.Operation) {
			continue
		}
		if mutator, ok := handler.(MutationInterface); ok {
			if err := mutator.Mutate(ctx, request, obj); err != nil {
				return err
			}
		}
	}
	return nil
}
