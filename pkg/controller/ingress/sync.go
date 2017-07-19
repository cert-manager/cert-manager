package ingress

import (
	extensions "k8s.io/api/extensions/v1beta1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
)

func (c *Controller) sync(ing *extensions.Ingress) error {
	// this ingress doesn't have a tls-acme annotation, so we'll ignore it
	if ing.Annotations == nil || ing.Annotations[certmanager.AnnotationIngressACMETLS] != "true" {
		return nil
	}

	crtLister := c.Context.CertManagerInformerFactory.Certmanager().V1alpha1().Certificates().Lister()

	// TODO (@munnerz): check if corresponding Certificate resource exists and
	// is up to date.
	// If not, create one now.

	return nil
}
