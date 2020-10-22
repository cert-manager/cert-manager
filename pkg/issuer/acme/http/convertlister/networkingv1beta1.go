package convertlister

import (
	"unsafe"

	"k8s.io/apimachinery/pkg/util/intstr"

	networkingv1listers "k8s.io/client-go/listers/networking/v1"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
	networkingv1beta1lister "k8s.io/client-go/listers/networking/v1beta1"
)

type Networkingv1beta1ConvertLister struct {
	lister    networkingv1beta1lister.IngressLister
	namespace string
}

// NewNetworkingv1beta1ConvertLister returns a networkingv1.IngressLister from a networkingv1beta1.IngressLister
func NewNetworkingv1beta1ConvertLister(lister networkingv1beta1lister.IngressLister) *Networkingv1beta1ConvertLister {
	return &Networkingv1beta1ConvertLister{
		lister:    lister,
		namespace: "",
	}
}

func (n *Networkingv1beta1ConvertLister) List(selector labels.Selector) ([]*networkingv1.Ingress, error) {
	var resp []*networkingv1beta1.Ingress
	var err error
	if n.namespace != "" {
		resp, err = n.lister.Ingresses(n.namespace).List(selector)
	} else {
		resp, err = n.lister.List(selector)
	}

	if err != nil {
		return nil, err
	}

	var out []*networkingv1.Ingress
	for _, oldIngress := range resp {
		newIngress := networkingv1.Ingress{}
		ConvertNetworkingV1beta1ToNetworkingV1Ingress(oldIngress, &newIngress)
		out = append(out, &newIngress)
	}

	return out, nil
}

func (n *Networkingv1beta1ConvertLister) Get(name string) (*networkingv1.Ingress, error) {
	resp, err := n.lister.Ingresses(n.namespace).Get(name)
	if err != nil {
		return nil, err
	}

	newIngress := networkingv1.Ingress{}
	ConvertNetworkingV1beta1ToNetworkingV1Ingress(resp, &newIngress)

	return &newIngress, nil
}

func (n *Networkingv1beta1ConvertLister) Ingresses(namespace string) networkingv1listers.IngressNamespaceLister {
	return &Networkingv1beta1ConvertLister{
		lister:    n.lister,
		namespace: namespace,
	}
}

// TODO: FIX
func ConvertNetworkingV1beta1ToNetworkingV1Ingress(in *networkingv1beta1.Ingress, out *networkingv1.Ingress) {
	out.ObjectMeta = in.ObjectMeta

	out.Spec.IngressClassName = (*string)(unsafe.Pointer(in.Spec.IngressClassName))
	out.Spec.TLS = *(*[]v1.IngressTLS)(unsafe.Pointer(&in.Spec.TLS))
	out.Spec.Rules = *(*[]v1.IngressRule)(unsafe.Pointer(&in.Spec.Rules))

	out.Status.LoadBalancer.Ingress = *(*[]corev1.LoadBalancerIngress)(unsafe.Pointer(&in.Status.LoadBalancer.Ingress))
}

// TODO: CONSOLIDATE
func ConvertNetworkingV1ToNetworkingV1beta1Ingress(in *networkingv1.Ingress, out *networkingv1beta1.Ingress) {
	out.ObjectMeta = in.ObjectMeta
	out.Spec.IngressClassName = (*string)(unsafe.Pointer(in.Spec.IngressClassName))
	out.Spec.TLS = *(*[]networkingv1beta1.IngressTLS)(unsafe.Pointer(&in.Spec.TLS))

	if in.Spec.Rules != nil {
		in, out := &in.Spec.Rules, &out.Spec.Rules
		*out = make([]networkingv1beta1.IngressRule, len(*in))
		for i := range *in {
			convert_networking_IngressRule_To_v1beta1_IngressRule(&(*in)[i], &(*out)[i])
		}
	} else {
		out.Spec.Rules = nil
	}

	out.Spec.IngressClassName = (*string)(unsafe.Pointer(in.Spec.IngressClassName))
	out.Spec.TLS = *(*[]networkingv1beta1.IngressTLS)(unsafe.Pointer(&in.Spec.TLS))
	out.Spec.Rules = *(*[]networkingv1beta1.IngressRule)(unsafe.Pointer(&in.Spec.Rules))

	out.Status.LoadBalancer.Ingress = *(*[]corev1.LoadBalancerIngress)(unsafe.Pointer(&in.Status.LoadBalancer.Ingress))
}

func convert_networking_IngressRule_To_v1beta1_IngressRule(in *networkingv1.IngressRule, out *networkingv1beta1.IngressRule) error {
	out.Host = in.Host
	if err := Convert_networking_IngressRuleValue_To_v1beta1_IngressRuleValue(&in.IngressRuleValue, &out.IngressRuleValue); err != nil {
		return err
	}
	return nil
}

func Convert_networking_IngressRuleValue_To_v1beta1_IngressRuleValue(in *networkingv1.IngressRuleValue, out *networkingv1beta1.IngressRuleValue) error {
	if in.HTTP != nil {
		in, out := &in.HTTP, &out.HTTP
		*out = new(networkingv1beta1.HTTPIngressRuleValue)
		if err := Convert_networking_HTTPIngressRuleValue_To_v1beta1_HTTPIngressRuleValue(*in, *out); err != nil {
			return err
		}
	} else {
		out.HTTP = nil
	}
	return nil
}

func Convert_networking_HTTPIngressRuleValue_To_v1beta1_HTTPIngressRuleValue(in *networkingv1.HTTPIngressRuleValue, out *networkingv1beta1.HTTPIngressRuleValue) error {
	if in.Paths != nil {
		in, out := &in.Paths, &out.Paths
		*out = make([]networkingv1beta1.HTTPIngressPath, len(*in))
		for i := range *in {
			if err := Convert_networking_HTTPIngressPath_To_v1beta1_HTTPIngressPath(&(*in)[i], &(*out)[i]); err != nil {
				return err
			}
		}
	} else {
		out.Paths = nil
	}
	return nil
}

func Convert_networking_HTTPIngressPath_To_v1beta1_HTTPIngressPath(in *networkingv1.HTTPIngressPath, out *networkingv1beta1.HTTPIngressPath) error {
	out.Path = in.Path
	out.PathType = (*networkingv1beta1.PathType)(unsafe.Pointer(in.PathType))
	out.Backend = networkingv1beta1.IngressBackend{}

	out.Backend.Resource = (*corev1.TypedLocalObjectReference)(unsafe.Pointer(in.Backend.Resource))
	if in.Backend.Service != nil {
		out.Backend.ServiceName = in.Backend.Service.Name
		if len(in.Backend.Service.Port.Name) > 0 {
			out.Backend.ServicePort = intstr.FromString(in.Backend.Service.Port.Name)
		} else {
			out.Backend.ServicePort = intstr.FromInt(int(in.Backend.Service.Port.Number))
		}
	}
	return nil
}
