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

package predicate

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func TestResourceOwnedBy(t *testing.T) {
	baseGVK := cmapi.SchemeGroupVersion.WithKind("CertificateRequest")
	request := func(name string) *cmapi.CertificateRequest {
		return &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name)}}
	}
	requestWithOwner := func(owner metav1.Object, gvk schema.GroupVersionKind) *cmapi.CertificateRequest {
		return &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(owner, gvk)},
			},
		}
	}
	tests := map[string]struct {
		owner    runtime.Object
		obj      runtime.Object
		expected bool
	}{
		"returns true if resource does own the resource": {
			owner:    request("base"),
			obj:      requestWithOwner(request("base"), baseGVK),
			expected: true,
		},
		"returns false if resource does not own the resource": {
			owner:    request("base"),
			obj:      requestWithOwner(request("notbase"), baseGVK),
			expected: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := ResourceOwnedBy(test.owner)(test.obj)
			if got != test.expected {
				t.Errorf("unexpected response: got=%t, exp=%t", got, test.expected)
			}
		})
	}
}

func TestResourceOwnerOf(t *testing.T) {
	baseGVK := cmapi.SchemeGroupVersion.WithKind("CertificateRequest")
	request := func(name string) *cmapi.CertificateRequest {
		return &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name)}}
	}
	requestWithOwner := func(owner metav1.Object, gvk schema.GroupVersionKind) *cmapi.CertificateRequest {
		return &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(owner, gvk)},
			},
		}
	}
	tests := map[string]struct {
		ownee    runtime.Object
		obj      runtime.Object
		expected bool
	}{
		"returns true if resource is owned by object": {
			ownee:    requestWithOwner(request("base"), baseGVK),
			obj:      request("base"),
			expected: true,
		},
		"returns false if resource is not owned by object": {
			ownee:    requestWithOwner(request("notbase"), baseGVK),
			obj:      request("base"),
			expected: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := ResourceOwnerOf(test.ownee)(test.obj)
			if got != test.expected {
				t.Errorf("unexpected response: got=%t, exp=%t", got, test.expected)
			}
		})
	}
}
