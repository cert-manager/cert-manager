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

package ingress

import (
	"unsafe"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/util/intstr"
)

/*
This file contains copies of functions from k8s.io/kubernetes,
as we definitely don't want to import the entire of k8s. The code
is released under the following LICENSE:
*/

/*
Copyright The Kubernetes Authors.
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

// Convert_networking_Ingress_To_v1beta1_Ingress uses unsafe pointer manipulation to manipulate a
// *networkingv1beta1.Ingress into pointing at the same underlying data as the input *networkingv1.Ingress.
// Both the `in` and `out` Object's data will be manipulated by this function.
//
// Recommended usage:
//  // as in and out will point to the same data, make sure any manipulation doesn't affect the original Ingress
//  in := myIngress.DeepCopy()
//  out := new(networkingv1beta1.Ingress)
//  err := Convert_networking_Ingress_To_v1beta1_Ingress(in, out, nil)
func Convert_networking_Ingress_To_v1beta1_Ingress(in *networkingv1.Ingress, out *networkingv1beta1.Ingress, s conversion.Scope) error {
	err := autoConvert_networking_Ingress_To_v1beta1_Ingress(in, out, s)
	if err != nil {
		return err
	}
	// v1beta1 Ingresses should not have IngressClassName set but instead use the deprecated annotation.
	// Move the ingress class to the annotations and then zero the IngressClassName field
	if out.Spec.IngressClassName != nil {
		if out.Annotations == nil {
			out.Annotations = make(map[string]string)
		}
		out.Annotations["kubernetes.io/ingress.class"] = *out.Spec.IngressClassName
		out.Spec.IngressClassName = nil
	}
	return nil
}

func autoConvert_networking_Ingress_To_v1beta1_Ingress(in *networkingv1.Ingress, out *networkingv1beta1.Ingress, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_networking_IngressSpec_To_v1beta1_IngressSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	if err := Convert_networking_IngressStatus_To_v1beta1_IngressStatus(&in.Status, &out.Status, s); err != nil {
		return err
	}
	return nil
}

func Convert_networking_IngressSpec_To_v1beta1_IngressSpec(in *networkingv1.IngressSpec, out *networkingv1beta1.IngressSpec, s conversion.Scope) error {
	if err := autoConvert_networking_IngressSpec_To_v1beta1_IngressSpec(in, out, s); err != nil {
		return nil
	}
	if in.DefaultBackend != nil {
		out.Backend = &networkingv1beta1.IngressBackend{}
		if err := Convert_networking_IngressBackend_To_v1beta1_IngressBackend(in.DefaultBackend, out.Backend, s); err != nil {
			return err
		}
	}
	return nil
}

func autoConvert_networking_IngressSpec_To_v1beta1_IngressSpec(in *networkingv1.IngressSpec, out *networkingv1beta1.IngressSpec, s conversion.Scope) error {
	out.IngressClassName = (*string)(unsafe.Pointer(in.IngressClassName))
	// WARNING: in.DefaultBackend requires manual conversion: does not exist in peer-type
	out.TLS = *(*[]networkingv1beta1.IngressTLS)(unsafe.Pointer(&in.TLS))
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = make([]networkingv1beta1.IngressRule, len(*in))
		for i := range *in {
			if err := Convert_networking_IngressRule_To_v1beta1_IngressRule(&(*in)[i], &(*out)[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Rules = nil
	}
	return nil
}

func Convert_networking_IngressStatus_To_v1beta1_IngressStatus(in *networkingv1.IngressStatus, out *networkingv1beta1.IngressStatus, s conversion.Scope) error {
	return autoConvert_networking_IngressStatus_To_v1beta1_IngressStatus(in, out, s)
}

func autoConvert_networking_IngressStatus_To_v1beta1_IngressStatus(in *networkingv1.IngressStatus, out *networkingv1beta1.IngressStatus, s conversion.Scope) error {
	if err := Convert_core_LoadBalancerStatus_To_v1_LoadBalancerStatus(&in.LoadBalancer, &out.LoadBalancer, s); err != nil {
		return err
	}
	return nil
}

func Convert_core_LoadBalancerStatus_To_v1_LoadBalancerStatus(in *corev1.LoadBalancerStatus, out *corev1.LoadBalancerStatus, s conversion.Scope) error {
	return autoConvert_core_LoadBalancerStatus_To_v1_LoadBalancerStatus(in, out, s)
}

func autoConvert_core_LoadBalancerStatus_To_v1_LoadBalancerStatus(in *corev1.LoadBalancerStatus, out *corev1.LoadBalancerStatus, s conversion.Scope) error {
	out.Ingress = *(*[]corev1.LoadBalancerIngress)(unsafe.Pointer(&in.Ingress))
	return nil
}

func Convert_networking_IngressRule_To_v1beta1_IngressRule(in *networkingv1.IngressRule, out *networkingv1beta1.IngressRule, s conversion.Scope) error {
	return autoConvert_networking_IngressRule_To_v1beta1_IngressRule(in, out, s)
}

func autoConvert_networking_IngressRule_To_v1beta1_IngressRule(in *networkingv1.IngressRule, out *networkingv1beta1.IngressRule, s conversion.Scope) error {
	out.Host = in.Host
	if err := Convert_networking_IngressRuleValue_To_v1beta1_IngressRuleValue(&in.IngressRuleValue, &out.IngressRuleValue, s); err != nil {
		return err
	}
	return nil
}

func Convert_networking_IngressRuleValue_To_v1beta1_IngressRuleValue(in *networkingv1.IngressRuleValue, out *networkingv1beta1.IngressRuleValue, s conversion.Scope) error {
	return autoConvert_networking_IngressRuleValue_To_v1beta1_IngressRuleValue(in, out, s)
}

func autoConvert_networking_IngressRuleValue_To_v1beta1_IngressRuleValue(in *networkingv1.IngressRuleValue, out *networkingv1beta1.IngressRuleValue, s conversion.Scope) error {
	if in.HTTP != nil {
		in, out := &in.HTTP, &out.HTTP
		*out = new(networkingv1beta1.HTTPIngressRuleValue)
		if err := Convert_networking_HTTPIngressRuleValue_To_v1beta1_HTTPIngressRuleValue(*in, *out, s); err != nil {
			return err
		}
	} else {
		out.HTTP = nil
	}
	return nil
}

func Convert_networking_HTTPIngressRuleValue_To_v1beta1_HTTPIngressRuleValue(in *networkingv1.HTTPIngressRuleValue, out *networkingv1beta1.HTTPIngressRuleValue, s conversion.Scope) error {
	return autoConvert_networking_HTTPIngressRuleValue_To_v1beta1_HTTPIngressRuleValue(in, out, s)
}

func autoConvert_networking_HTTPIngressRuleValue_To_v1beta1_HTTPIngressRuleValue(in *networkingv1.HTTPIngressRuleValue, out *networkingv1beta1.HTTPIngressRuleValue, s conversion.Scope) error {
	if in.Paths != nil {
		in, out := &in.Paths, &out.Paths
		*out = make([]networkingv1beta1.HTTPIngressPath, len(*in))
		for i := range *in {
			if err := Convert_networking_HTTPIngressPath_To_v1beta1_HTTPIngressPath(&(*in)[i], &(*out)[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Paths = nil
	}
	return nil
}

func Convert_networking_HTTPIngressPath_To_v1beta1_HTTPIngressPath(in *networkingv1.HTTPIngressPath, out *networkingv1beta1.HTTPIngressPath, s conversion.Scope) error {
	return autoConvert_networking_HTTPIngressPath_To_v1beta1_HTTPIngressPath(in, out, s)
}

func autoConvert_networking_HTTPIngressPath_To_v1beta1_HTTPIngressPath(in *networkingv1.HTTPIngressPath, out *networkingv1beta1.HTTPIngressPath, s conversion.Scope) error {
	out.Path = in.Path
	out.PathType = (*networkingv1beta1.PathType)(unsafe.Pointer(in.PathType))
	if err := Convert_networking_IngressBackend_To_v1beta1_IngressBackend(&in.Backend, &out.Backend, s); err != nil {
		return err
	}
	return nil
}

func Convert_networking_IngressBackend_To_v1beta1_IngressBackend(in *networkingv1.IngressBackend, out *networkingv1beta1.IngressBackend, s conversion.Scope) error {
	if err := autoConvert_networking_IngressBackend_To_v1beta1_IngressBackend(in, out, s); err != nil {
		return err
	}
	if in.Service != nil {
		out.ServiceName = in.Service.Name
		if len(in.Service.Port.Name) > 0 {
			out.ServicePort = intstr.FromString(in.Service.Port.Name)
		} else {
			out.ServicePort = intstr.FromInt(int(in.Service.Port.Number))
		}
	}
	return nil
}

func autoConvert_networking_IngressBackend_To_v1beta1_IngressBackend(in *networkingv1.IngressBackend, out *networkingv1beta1.IngressBackend, s conversion.Scope) error {
	// WARNING: in.Service requires manual conversion: does not exist in peer-type
	out.Resource = (*corev1.TypedLocalObjectReference)(unsafe.Pointer(in.Resource))
	return nil
}

// Convert_v1beta1_Ingress_To_networking_Ingress uses unsafe pointer manipulation to manipulate a
// *networkingv1.Ingress into pointing at the same underlying data as the input *networkingv1beta1.Ingress.
// Both the `in` and `out` Object's data will be manipulated by this function.
//
// Recommended usage:
//  // as in and out will point to the same data, make sure any manipulation doesn't affect the original Ingress
//  in := myIngress.DeepCopy()
//  out := new(networkingv1.Ingress)
//  err := Convert_v1beta1_Ingress_To_networking_Ingress(in, out, nil)
func Convert_v1beta1_Ingress_To_networking_Ingress(in *networkingv1beta1.Ingress, out *networkingv1.Ingress, s conversion.Scope) error {
	err := autoConvert_v1beta1_Ingress_To_networking_Ingress(in, out, s)
	if err != nil {
		return err
	}
	// v1beta1 Ingresses should not have IngressClassName set but instead use the deprecated annotation.
	// Move the ingress class from the annotations to the Spec
	if in.Annotations == nil {
		return nil
	}
	if ingressClass, found := in.Annotations["kubernetes.io/ingress.class"]; found {
		out.Spec.IngressClassName = &ingressClass
		// HERE BE DRAGONS:
		// in.Annotations and out.Annotations point to the same map.
		// This mutates in as well as out, so make sure in is not an object in
		// client-go's cache, for example by only passing DeepCopy()d objects
		// to Convert_v1beta1_Ingress_To_networking_Ingress
		delete(out.Annotations, "kubernetes.io/ingress.class")
	}
	return nil
}

func autoConvert_v1beta1_Ingress_To_networking_Ingress(in *networkingv1beta1.Ingress, out *networkingv1.Ingress, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1beta1_IngressSpec_To_networking_IngressSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	if err := Convert_v1beta1_IngressStatus_To_networking_IngressStatus(&in.Status, &out.Status, s); err != nil {
		return err
	}
	return nil
}

func Convert_v1beta1_IngressSpec_To_networking_IngressSpec(in *networkingv1beta1.IngressSpec, out *networkingv1.IngressSpec, s conversion.Scope) error {
	if err := autoConvert_v1beta1_IngressSpec_To_networking_IngressSpec(in, out, s); err != nil {
		return nil
	}
	if in.Backend != nil {
		out.DefaultBackend = &networkingv1.IngressBackend{}
		if err := Convert_v1beta1_IngressBackend_To_networking_IngressBackend(in.Backend, out.DefaultBackend, s); err != nil {
			return err
		}
	}
	return nil
}

func autoConvert_v1beta1_IngressSpec_To_networking_IngressSpec(in *networkingv1beta1.IngressSpec, out *networkingv1.IngressSpec, s conversion.Scope) error {
	out.IngressClassName = (*string)(unsafe.Pointer(in.IngressClassName))
	// WARNING: in.Backend requires manual conversion: does not exist in peer-type
	out.TLS = *(*[]networkingv1.IngressTLS)(unsafe.Pointer(&in.TLS))
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = make([]networkingv1.IngressRule, len(*in))
		for i := range *in {
			if err := Convert_v1beta1_IngressRule_To_networking_IngressRule(&(*in)[i], &(*out)[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Rules = nil
	}
	return nil
}

func Convert_v1beta1_IngressStatus_To_networking_IngressStatus(in *networkingv1beta1.IngressStatus, out *networkingv1.IngressStatus, s conversion.Scope) error {
	return autoConvert_v1beta1_IngressStatus_To_networking_IngressStatus(in, out, s)
}

func autoConvert_v1beta1_IngressStatus_To_networking_IngressStatus(in *networkingv1beta1.IngressStatus, out *networkingv1.IngressStatus, s conversion.Scope) error {
	if err := Convert_v1_LoadBalancerStatus_To_core_LoadBalancerStatus(&in.LoadBalancer, &out.LoadBalancer, s); err != nil {
		return err
	}
	return nil
}

func Convert_v1_LoadBalancerStatus_To_core_LoadBalancerStatus(in *corev1.LoadBalancerStatus, out *corev1.LoadBalancerStatus, s conversion.Scope) error {
	return autoConvert_v1_LoadBalancerStatus_To_core_LoadBalancerStatus(in, out, s)
}

func autoConvert_v1_LoadBalancerStatus_To_core_LoadBalancerStatus(in *corev1.LoadBalancerStatus, out *corev1.LoadBalancerStatus, s conversion.Scope) error {
	out.Ingress = *(*[]corev1.LoadBalancerIngress)(unsafe.Pointer(&in.Ingress))
	return nil
}

func Convert_v1beta1_IngressRule_To_networking_IngressRule(in *networkingv1beta1.IngressRule, out *networkingv1.IngressRule, s conversion.Scope) error {
	return autoConvert_v1beta1_IngressRule_To_networking_IngressRule(in, out, s)
}

func autoConvert_v1beta1_IngressRule_To_networking_IngressRule(in *networkingv1beta1.IngressRule, out *networkingv1.IngressRule, s conversion.Scope) error {
	out.Host = in.Host
	if err := Convert_v1beta1_IngressRuleValue_To_networking_IngressRuleValue(&in.IngressRuleValue, &out.IngressRuleValue, s); err != nil {
		return err
	}
	return nil
}

func Convert_v1beta1_IngressRuleValue_To_networking_IngressRuleValue(in *networkingv1beta1.IngressRuleValue, out *networkingv1.IngressRuleValue, s conversion.Scope) error {
	return autoConvert_v1beta1_IngressRuleValue_To_networking_IngressRuleValue(in, out, s)
}

func autoConvert_v1beta1_IngressRuleValue_To_networking_IngressRuleValue(in *networkingv1beta1.IngressRuleValue, out *networkingv1.IngressRuleValue, s conversion.Scope) error {
	if in.HTTP != nil {
		in, out := &in.HTTP, &out.HTTP
		*out = new(networkingv1.HTTPIngressRuleValue)
		if err := Convert_v1beta1_HTTPIngressRuleValue_To_networking_HTTPIngressRuleValue(*in, *out, s); err != nil {
			return err
		}
	} else {
		out.HTTP = nil
	}
	return nil
}

func Convert_v1beta1_HTTPIngressRuleValue_To_networking_HTTPIngressRuleValue(in *networkingv1beta1.HTTPIngressRuleValue, out *networkingv1.HTTPIngressRuleValue, s conversion.Scope) error {
	return autoConvert_v1beta1_HTTPIngressRuleValue_To_networking_HTTPIngressRuleValue(in, out, s)
}

func autoConvert_v1beta1_HTTPIngressRuleValue_To_networking_HTTPIngressRuleValue(in *networkingv1beta1.HTTPIngressRuleValue, out *networkingv1.HTTPIngressRuleValue, s conversion.Scope) error {
	if in.Paths != nil {
		in, out := &in.Paths, &out.Paths
		*out = make([]networkingv1.HTTPIngressPath, len(*in))
		for i := range *in {
			if err := Convert_v1beta1_HTTPIngressPath_To_networking_HTTPIngressPath(&(*in)[i], &(*out)[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Paths = nil
	}
	return nil
}

func Convert_v1beta1_HTTPIngressPath_To_networking_HTTPIngressPath(in *networkingv1beta1.HTTPIngressPath, out *networkingv1.HTTPIngressPath, s conversion.Scope) error {
	return autoConvert_v1beta1_HTTPIngressPath_To_networking_HTTPIngressPath(in, out, s)
}

func autoConvert_v1beta1_HTTPIngressPath_To_networking_HTTPIngressPath(in *networkingv1beta1.HTTPIngressPath, out *networkingv1.HTTPIngressPath, s conversion.Scope) error {
	out.Path = in.Path
	out.PathType = (*networkingv1.PathType)(unsafe.Pointer(in.PathType))
	if err := Convert_v1beta1_IngressBackend_To_networking_IngressBackend(&in.Backend, &out.Backend, s); err != nil {
		return err
	}
	return nil
}

func Convert_v1beta1_IngressBackend_To_networking_IngressBackend(in *networkingv1beta1.IngressBackend, out *networkingv1.IngressBackend, s conversion.Scope) error {
	if err := autoConvert_v1beta1_IngressBackend_To_networking_IngressBackend(in, out, s); err != nil {
		return err
	}
	if len(in.ServiceName) > 0 || in.ServicePort.IntVal != 0 || in.ServicePort.StrVal != "" || in.ServicePort.Type == intstr.String {
		out.Service = &networkingv1.IngressServiceBackend{}
		out.Service.Name = in.ServiceName
		out.Service.Port.Name = in.ServicePort.StrVal
		out.Service.Port.Number = in.ServicePort.IntVal
	}
	return nil
}

func autoConvert_v1beta1_IngressBackend_To_networking_IngressBackend(in *networkingv1beta1.IngressBackend, out *networkingv1.IngressBackend, s conversion.Scope) error {
	// WARNING: in.ServiceName requires manual conversion: does not exist in peer-type
	// WARNING: in.ServicePort requires manual conversion: does not exist in peer-type
	out.Resource = (*corev1.TypedLocalObjectReference)(unsafe.Pointer(in.Resource))
	return nil
}
