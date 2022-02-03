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

package handlers

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2/klogr"
	"k8s.io/utils/diff"

	"github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup"
	"github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/install"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestConvertTestType(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)

	log := klogr.New()
	c := NewSchemeBackedConverter(log, scheme)

	type conversionTestT struct {
		inputRequest     apiextensionsv1.ConversionRequest
		expectedResponse apiextensionsv1.ConversionResponse
	}

	tests := map[string]conversionTestT{
		"correctly handles requests with multiple input items": {
			inputRequest: apiextensionsv1.ConversionRequest{
				DesiredAPIVersion: testgroup.GroupName + "/v1",
				Objects: []runtime.RawExtension{
					{
						Raw: []byte(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	}
}
`),
					},
					{
						Raw: []byte(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	}
}
`),
					},
				},
			},
			expectedResponse: apiextensionsv1.ConversionResponse{
				Result: metav1.Status{
					Status: metav1.StatusSuccess,
				},
				ConvertedObjects: []runtime.RawExtension{
					{
						Raw: []byte(`{"kind":"TestType","apiVersion":"testgroup.testing.cert-manager.io/v1","metadata":{"name":"testing","namespace":"abc","creationTimestamp":null},"testField":"","testFieldImmutable":""}
`),
					},
					{
						Raw: []byte(`{"kind":"TestType","apiVersion":"testgroup.testing.cert-manager.io/v1","metadata":{"name":"testing","namespace":"abc","creationTimestamp":null},"testField":"","testFieldImmutable":""}
`),
					},
				},
			},
		},
		"succeeds when handling requests with no input items": {
			inputRequest: apiextensionsv1.ConversionRequest{
				DesiredAPIVersion: testgroup.GroupName + "/v1",
				Objects:           []runtime.RawExtension{},
			},
			expectedResponse: apiextensionsv1.ConversionResponse{
				Result: metav1.Status{
					Status: metav1.StatusSuccess,
				},
				ConvertedObjects: []runtime.RawExtension{},
			},
		},
		"copies across request UID to the response field": {
			inputRequest: apiextensionsv1.ConversionRequest{
				DesiredAPIVersion: testgroup.GroupName + "/v1",
				Objects:           []runtime.RawExtension{},
				UID:               types.UID("abc"),
			},
			expectedResponse: apiextensionsv1.ConversionResponse{
				Result: metav1.Status{
					Status: metav1.StatusSuccess,
				},
				UID:              types.UID("abc"),
				ConvertedObjects: []runtime.RawExtension{},
			},
		},
		"converts from v1 to v1 without applying defaults": {
			inputRequest: apiextensionsv1.ConversionRequest{
				DesiredAPIVersion: testgroup.GroupName + "/v1",
				Objects: []runtime.RawExtension{
					{
						Raw: []byte(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	}
}
`),
					},
				},
			},
			expectedResponse: apiextensionsv1.ConversionResponse{
				Result: metav1.Status{
					Status: metav1.StatusSuccess,
				},
				ConvertedObjects: []runtime.RawExtension{
					{
						Raw: []byte(`{"kind":"TestType","apiVersion":"testgroup.testing.cert-manager.io/v1","metadata":{"name":"testing","namespace":"abc","creationTimestamp":null},"testField":"","testFieldImmutable":""}
`),
					},
				},
			},
		},
		"converts from v1 to v2 without applying defaults": {
			inputRequest: apiextensionsv1.ConversionRequest{
				DesiredAPIVersion: testgroup.GroupName + "/v2",
				Objects: []runtime.RawExtension{
					{
						Raw: []byte(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	}
}
`),
					},
				},
			},
			expectedResponse: apiextensionsv1.ConversionResponse{
				Result: metav1.Status{
					Status: metav1.StatusSuccess,
				},
				ConvertedObjects: []runtime.RawExtension{
					{
						Raw: []byte(`{"kind":"TestType","apiVersion":"testgroup.testing.cert-manager.io/v2","metadata":{"name":"testing","namespace":"abc","creationTimestamp":null},"testField":"","testFieldImmutable":""}
`),
					},
				},
			},
		},
		"converts from v1 to v2": {
			inputRequest: apiextensionsv1.ConversionRequest{
				DesiredAPIVersion: testgroup.GroupName + "/v2",
				Objects: []runtime.RawExtension{
					{
						Raw: []byte(`
{
	"apiVersion": "testgroup.testing.cert-manager.io/v1",
	"kind": "TestType",
	"metadata": {
		"name": "testing",
		"namespace": "abc",
		"creationTimestamp": null
	},
	"testField": "atest",
	"testFieldPtr": "something"
}
`),
					},
				},
			},
			expectedResponse: apiextensionsv1.ConversionResponse{
				Result: metav1.Status{
					Status: metav1.StatusSuccess,
				},
				ConvertedObjects: []runtime.RawExtension{
					{
						Raw: []byte(`{"kind":"TestType","apiVersion":"testgroup.testing.cert-manager.io/v2","metadata":{"name":"testing","namespace":"abc","creationTimestamp":null},"testField":"atest","testFieldPtrAlt":"something","testFieldImmutable":""}
`),
					},
				},
			},
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			resp := c.Convert(&test.inputRequest)
			if !reflect.DeepEqual(&test.expectedResponse, resp) {
				t.Errorf("Response was not as expected: %v", diff.ObjectGoPrintSideBySide(&test.expectedResponse, resp))
			}
		})
	}
}
