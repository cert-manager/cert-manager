package clusterissuers

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (c *Controller) issuersForSecret(secret *corev1.Secret) ([]*v1alpha1.ClusterIssuer, error) {
	issuers, err := c.issuerLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificiates: %s", err.Error())
	}

	var affected []*v1alpha1.ClusterIssuer
	for _, iss := range issuers {
		if secret.Namespace != c.clusterResourceNamespace {
			continue
		}
		if (iss.Spec.ACME != nil && iss.Spec.ACME.PrivateKey.Name == secret.Name) ||
			(iss.Spec.CA != nil && iss.Spec.CA.SecretName == secret.Name) ||
			(iss.Spec.Vault != nil && iss.Spec.Vault.Auth.TokenSecretRef.Name == secret.Name) {
			affected = append(affected, iss)
			continue
		}
	}

	return affected, nil
}
