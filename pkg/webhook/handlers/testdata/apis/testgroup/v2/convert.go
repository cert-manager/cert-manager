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

package v2

import (
	"unsafe"

	"k8s.io/apimachinery/pkg/conversion"

	"github.com/cert-manager/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup"
)

func Convert_v2_TestType_To_testgroup_TestType(in *TestType, out *testgroup.TestType, s conversion.Scope) error {
	if err := autoConvert_v2_TestType_To_testgroup_TestType(in, out, s); err != nil {
		return err
	}
	out.TestFieldPtr = (*string)(unsafe.Pointer(in.TestFieldPtrAlt))
	return nil
}

func Convert_testgroup_TestType_To_v2_TestType(in *testgroup.TestType, out *TestType, s conversion.Scope) error {
	if err := autoConvert_testgroup_TestType_To_v2_TestType(in, out, s); err != nil {
		return err
	}
	out.TestFieldPtrAlt = (*string)(unsafe.Pointer(in.TestFieldPtr))
	return nil
}
