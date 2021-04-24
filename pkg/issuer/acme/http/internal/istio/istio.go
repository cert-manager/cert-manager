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

// By utilising this file, no dependance on `istio.io/client-go` is
// required. Used in combination with a dynamic client, it is possible
// to create a client for these CRDs without adding a client-go dependency.
// Based on: https://github.com/istio/client-go/blob/4c970a7c677150c96c4381118821b36c52e4c7b7/pkg/apis/networking/v1beta1/types.gen.go#L249-L269
// TODO: remove this file in favour of Istio API types without client-go dependency https://github.com/istio/api/issues/1959

package istio

import (
	v1alpha1 "istio.io/api/meta/v1alpha1"
	networkingv1beta1 "istio.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	virtualServiceGvk = schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1beta1", Kind: "VirtualService"}
	virtualServiceGvr = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1beta1", Resource: "virtualservices"}
)

func VirtualServiceGvr() schema.GroupVersionResource {
	return virtualServiceGvr
}

type VirtualService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the implementation of this definition.
	Spec networkingv1beta1.VirtualService `json:"spec,omitempty"`

	Status v1alpha1.IstioStatus `json:"status"`
}

// VirtualServiceList is a collection of VirtualServices.
type VirtualServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualService `json:"items"`
}

func (virtualService *VirtualService) ToUnstructured() (*unstructured.Unstructured, error) {
	virtualService.TypeMeta.SetGroupVersionKind(virtualServiceGvk)
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(virtualService)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: unstructuredObj}, nil
}

func VirtualServiceFromUnstructured(unstr *unstructured.Unstructured) (*VirtualService, error) {
	var virtualService VirtualService
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstr.UnstructuredContent(), &virtualService)
	if err != nil {
		return nil, err
	}
	return &virtualService, nil
}
