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

package v1

import (
	"k8s.io/apimachinery/pkg/conversion"

	"github.com/jetstack/cert-manager/internal/apis/meta"
	"github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

// Convert_meta_LocalObjectReference_To_v1_LocalObjectReference is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_meta_LocalObjectReference_To_v1_LocalObjectReference(in *meta.LocalObjectReference, out *v1.LocalObjectReference, s conversion.Scope) error {
	return autoConvert_meta_LocalObjectReference_To_v1_LocalObjectReference(in, out, s)
}

// Convert_v1_LocalObjectReference_To_meta_LocalObjectReference is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_v1_LocalObjectReference_To_meta_LocalObjectReference(in *v1.LocalObjectReference, out *meta.LocalObjectReference, s conversion.Scope) error {
	return autoConvert_v1_LocalObjectReference_To_meta_LocalObjectReference(in, out, s)
}

// Convert_meta_ObjectReference_To_v1_ObjectReference is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_meta_ObjectReference_To_v1_ObjectReference(in *meta.ObjectReference, out *v1.ObjectReference, s conversion.Scope) error {
	return autoConvert_meta_ObjectReference_To_v1_ObjectReference(in, out, s)
}

// Convert_v1_ObjectReference_To_meta_ObjectReference is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_v1_ObjectReference_To_meta_ObjectReference(in *v1.ObjectReference, out *meta.ObjectReference, s conversion.Scope) error {
	return autoConvert_v1_ObjectReference_To_meta_ObjectReference(in, out, s)
}

// Convert_meta_SecretKeySelector_To_v1_SecretKeySelector is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_meta_SecretKeySelector_To_v1_SecretKeySelector(in *meta.SecretKeySelector, out *v1.SecretKeySelector, s conversion.Scope) error {
	return autoConvert_meta_SecretKeySelector_To_v1_SecretKeySelector(in, out, s)
}

// Convert_v1_SecretKeySelector_To_meta_SecretKeySelector is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_v1_SecretKeySelector_To_meta_SecretKeySelector(in *v1.SecretKeySelector, out *meta.SecretKeySelector, s conversion.Scope) error {
	return autoConvert_v1_SecretKeySelector_To_meta_SecretKeySelector(in, out, s)
}
