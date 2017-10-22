package certificates

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (c *Controller) certificatesForSecret(secret *corev1.Secret) ([]*v1alpha1.Certificate, error) {
	crts, err := c.certificateLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificiates: %s", err.Error())
	}

	var affected []*v1alpha1.Certificate
	for _, crt := range crts {
		if crt.Namespace != secret.Namespace {
			continue
		}
		if crt.Spec.SecretName == secret.Name {
			affected = append(affected, crt)
		}
	}

	return affected, nil
}

func (c *Controller) certificatesForIngress(ing *extv1beta1.Ingress) ([]*v1alpha1.Certificate, error) {
	crts, err := c.certificateLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificiates: %s", err.Error())
	}

	var affected []*v1alpha1.Certificate
	for _, crt := range crts {
		if crt.Namespace != ing.Namespace {
			continue
		}
		if crt.Spec.ACME != nil {
			for _, cfg := range crt.Spec.ACME.Config {
				if cfg.HTTP01 == nil {
					continue
				}
				if cfg.HTTP01.Ingress == ing.Name {
					affected = append(affected, crt)
					continue
				}
			}
		}
	}

	return affected, nil
}
