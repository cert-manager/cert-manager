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

package util

import (
	"unsafe"

	admissionv1 "k8s.io/api/admission/v1"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// these conversions are copied from https://github.com/kubernetes/kubernetes/blob/4db3a096ce8ac730b2280494422e1c4cf5fe875e/pkg/apis/admission/v1beta1/zz_generated.conversion.go
// to avoid copying in kubernetes/kubernetes
// they are slightly modified to remove complexity

func Convert_v1beta1_AdmissionReview_To_admission_AdmissionReview(in *admissionv1beta1.AdmissionReview, out *admissionv1.AdmissionReview) {
	if in.Request != nil {
		if out.Request == nil {
			out.Request = &admissionv1.AdmissionRequest{}
		}
		in, out := &in.Request, &out.Request
		*out = new(admissionv1.AdmissionRequest)
		Convert_v1beta1_AdmissionRequest_To_admission_AdmissionRequest(*in, *out)
	} else {
		out.Request = nil
	}
	out.Response = (*admissionv1.AdmissionResponse)(unsafe.Pointer(in.Response))
}

func Convert_v1beta1_AdmissionRequest_To_admission_AdmissionRequest(in *admissionv1beta1.AdmissionRequest, out *admissionv1.AdmissionRequest) {
	out.UID = types.UID(in.UID)
	out.Kind = in.Kind
	out.Resource = in.Resource
	out.SubResource = in.SubResource
	out.RequestKind = (*metav1.GroupVersionKind)(unsafe.Pointer(in.RequestKind))
	out.RequestResource = (*metav1.GroupVersionResource)(unsafe.Pointer(in.RequestResource))
	out.RequestSubResource = in.RequestSubResource
	out.Name = in.Name
	out.Namespace = in.Namespace
	out.Operation = admissionv1.Operation(in.Operation)
	out.Object = in.Object
	out.OldObject = in.OldObject
	out.Options = in.Options
}

func Convert_admission_AdmissionReview_To_v1beta1_AdmissionReview(in *admissionv1.AdmissionReview, out *admissionv1beta1.AdmissionReview) {
	if in.Request != nil {
		if out.Request == nil {
			out.Request = &admissionv1beta1.AdmissionRequest{}
		}
		in, out := &in.Request, &out.Request
		*out = new(admissionv1beta1.AdmissionRequest)
		Convert_admission_AdmissionRequest_To_v1beta1_AdmissionRequest(*in, *out)
	} else {
		out.Request = nil
	}
	out.Response = (*admissionv1beta1.AdmissionResponse)(unsafe.Pointer(in.Response))
}

func Convert_admission_AdmissionRequest_To_v1beta1_AdmissionRequest(in *admissionv1.AdmissionRequest, out *admissionv1beta1.AdmissionRequest) {
	out.UID = types.UID(in.UID)
	out.Kind = in.Kind
	out.Resource = in.Resource
	out.SubResource = in.SubResource
	out.RequestKind = (*metav1.GroupVersionKind)(unsafe.Pointer(in.RequestKind))
	out.RequestResource = (*metav1.GroupVersionResource)(unsafe.Pointer(in.RequestResource))
	out.RequestSubResource = in.RequestSubResource
	out.Name = in.Name
	out.Namespace = in.Namespace
	out.Operation = admissionv1beta1.Operation(in.Operation)
	out.Object = in.Object
	out.OldObject = in.OldObject
	out.Options = in.Options
}
