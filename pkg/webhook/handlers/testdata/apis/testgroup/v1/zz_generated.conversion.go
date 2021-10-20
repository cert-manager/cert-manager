//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright The cert-manager Authors.

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

// Code generated by conversion-gen. DO NOT EDIT.

package v1

import (
	unsafe "unsafe"

	testgroup "github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*TestType)(nil), (*testgroup.TestType)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1_TestType_To_testgroup_TestType(a.(*TestType), b.(*testgroup.TestType), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*testgroup.TestType)(nil), (*TestType)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_testgroup_TestType_To_v1_TestType(a.(*testgroup.TestType), b.(*TestType), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1_TestType_To_testgroup_TestType(in *TestType, out *testgroup.TestType, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.TestField = in.TestField
	out.TestFieldPtr = (*string)(unsafe.Pointer(in.TestFieldPtr))
	out.TestFieldImmutable = in.TestFieldImmutable
	return nil
}

// Convert_v1_TestType_To_testgroup_TestType is an autogenerated conversion function.
func Convert_v1_TestType_To_testgroup_TestType(in *TestType, out *testgroup.TestType, s conversion.Scope) error {
	return autoConvert_v1_TestType_To_testgroup_TestType(in, out, s)
}

func autoConvert_testgroup_TestType_To_v1_TestType(in *testgroup.TestType, out *TestType, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.TestField = in.TestField
	out.TestFieldPtr = (*string)(unsafe.Pointer(in.TestFieldPtr))
	out.TestFieldImmutable = in.TestFieldImmutable
	return nil
}

// Convert_testgroup_TestType_To_v1_TestType is an autogenerated conversion function.
func Convert_testgroup_TestType_To_v1_TestType(in *testgroup.TestType, out *TestType, s conversion.Scope) error {
	return autoConvert_testgroup_TestType_To_v1_TestType(in, out, s)
}
