package controller

import (
	"fmt"

	extv1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (c *Controller) ingressesForCertificate(crt *v1alpha1.Certificate) ([]*extv1beta1.Ingress, error) {
	ings, err := c.ingressLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificiates: %s", err.Error())
	}

	var affected []*extv1beta1.Ingress
	for _, ing := range ings {
		if crt.Namespace != ing.Namespace {
			continue
		}

		if metav1.IsControlledBy(crt, ing) {
			affected = append(affected, ing)
		}
	}

	return affected, nil
}
