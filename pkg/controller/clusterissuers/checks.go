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

package clusterissuers

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func (c *controller) issuersForSecret(secret *corev1.Secret) ([]*v1.ClusterIssuer, error) {
	issuers, err := c.clusterIssuerLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing issuers: %s", err.Error())
	}

	var affected []*v1.ClusterIssuer
	for _, iss := range issuers {
		if secret.Namespace != c.clusterResourceNamespace {
			continue
		}
		switch {
		case iss.Spec.ACME != nil:
			if iss.Spec.ACME.PrivateKey.Name == secret.Name {
				affected = append(affected, iss)
				continue
			}
			if iss.Spec.ACME.ExternalAccountBinding != nil {
				if iss.Spec.ACME.ExternalAccountBinding.Key.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
		case iss.Spec.CA != nil:
			if iss.Spec.CA.SecretName == secret.Name {
				affected = append(affected, iss)
				continue
			}
		case iss.Spec.Venafi != nil:
			if iss.Spec.Venafi.TPP != nil {
				if iss.Spec.Venafi.TPP.CredentialsRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
				if iss.Spec.Venafi.TPP.CABundleSecretRef != nil {
					if iss.Spec.Venafi.TPP.CABundleSecretRef.Name == secret.Name {
						affected = append(affected, iss)
						continue
					}
				}
			}
			if iss.Spec.Venafi.Cloud != nil {
				if iss.Spec.Venafi.Cloud.APITokenSecretRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
		case iss.Spec.Vault != nil:
			if iss.Spec.Vault.Auth.TokenSecretRef != nil {
				if iss.Spec.Vault.Auth.TokenSecretRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
			if iss.Spec.Vault.Auth.AppRole != nil {
				if iss.Spec.Vault.Auth.AppRole.SecretRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
			if iss.Spec.Vault.Auth.Kubernetes != nil {
				if iss.Spec.Vault.Auth.Kubernetes.SecretRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
			if iss.Spec.Vault.CABundleSecretRef != nil {
				if iss.Spec.Vault.CABundleSecretRef.Name == secret.Name {
					affected = append(affected, iss)
					continue
				}
			}
		}
	}

	return affected, nil
}
