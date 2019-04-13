/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package issuers

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (c *Controller) issuersForSecret(secret *corev1.Secret) ([]*v1alpha1.Issuer, error) {
	issuers, err := c.issuerLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificiates: %s", err.Error())
	}

	var affected []*v1alpha1.Issuer
	for _, iss := range issuers {
		if iss.Namespace != secret.Namespace {
			continue
		}
		if (iss.Spec.ACME != nil && iss.Spec.ACME.PrivateKey.Name == secret.Name) ||
			(iss.Spec.CA != nil && iss.Spec.CA.SecretName == secret.Name) ||
			(iss.Spec.Vault != nil && iss.Spec.Vault.Auth.TokenSecretRef.Name == secret.Name) ||
			(iss.Spec.Venafi != nil && iss.Spec.Venafi.TPP != nil && iss.Spec.Venafi.TPP.CredentialsRef.Name == secret.Name) ||
			(iss.Spec.Venafi != nil && iss.Spec.Venafi.Cloud != nil && iss.Spec.Venafi.Cloud.APITokenSecretRef.Name == secret.Name) {
			affected = append(affected, iss)
			continue
		}
	}

	return affected, nil
}
