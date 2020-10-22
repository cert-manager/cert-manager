package convertlister

import (
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	extensionsv1beta1 "k8s.io/client-go/listers/extensions/v1beta1"
	networkingv1listers "k8s.io/client-go/listers/networking/v1"
)

type Extensionsv1beta1ConvertLister struct {
	lister extensionsv1beta1.IngressLister
}

// NewExtensionsv1beta1ConvertLister returns a networkingv1.IngressLister from a extensionsv1beta1.IngressLister
func NewExtensionsv1beta1ConvertLister(lister extensionsv1beta1.IngressLister) *Extensionsv1beta1ConvertLister {
	return &Extensionsv1beta1ConvertLister{
		lister,
	}
}

func (e *Extensionsv1beta1ConvertLister) List(selector labels.Selector) (ret []*networkingv1.Ingress, err error) {
	// TODO
	return nil, nil
}

func (e *Extensionsv1beta1ConvertLister) Ingresses(namespace string) networkingv1listers.IngressNamespaceLister {
	return nil
}
