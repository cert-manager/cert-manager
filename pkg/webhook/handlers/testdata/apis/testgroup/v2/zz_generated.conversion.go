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

package v2

import (
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
	if err := s.AddConversionFunc((*testgroup.TestType)(nil), (*TestType)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_testgroup_TestType_To_v2_TestType(a.(*testgroup.TestType), b.(*TestType), scope)
	}); err != nil {
		return err
	}
	if err := s.AddConversionFunc((*TestType)(nil), (*testgroup.TestType)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v2_TestType_To_testgroup_TestType(a.(*TestType), b.(*testgroup.TestType), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v2_TestType_To_testgroup_TestType(in *TestType, out *testgroup.TestType, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.TestField = in.TestField
	// WARNING: in.TestFieldPtrAlt requires manual conversion: does not exist in peer-type
	out.TestFieldImmutable = in.TestFieldImmutable
	return nil
}

func autoConvert_testgroup_TestType_To_v2_TestType(in *testgroup.TestType, out *TestType, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.TestField = in.TestField
	// WARNING: in.TestFieldPtr requires manual conversion: does not exist in peer-type
	out.TestFieldImmutable = in.TestFieldImmutable
	return nil
}
