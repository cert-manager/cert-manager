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

package issuers

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/cert-manager/cert-manager/pkg/acme"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// issuersForSecret returns Issuers that reference the given Secret so Secret
// events can re-queue the right issuers.
//
// TODO(hjoshi123, wallrj): This walks every Issuer on each Secret event
// (O(numIssuers)). ACME DNS-01 matching also runs RequiredDNS01SolverSecrets
// per Issuer (extra conversion). Under high Secret churn that is expensive;
// index Issuers by referenced Secret names for O(1)/O(related) lookup.
// Deferred so the Ready=False re-queue fix (#9036) can land first.
func (c *controller) issuersForSecret(secret *corev1.Secret) ([]*v1.Issuer, error) {
	issuers, err := c.issuerLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing issuers: %w", err)
	}

	var affected []*v1.Issuer
	for _, iss := range issuers {
		// only applicable for Issuer resources
		if iss.Namespace != secret.Namespace {
			continue
		}

		switch {
		case iss.Spec.ACME != nil:
			if iss.Spec.ACME.PrivateKey.Name == secret.Name {
				affected = append(affected, iss)
				continue
			}
			if iss.Spec.ACME.ExternalAccountBinding != nil && iss.Spec.ACME.ExternalAccountBinding.Key.Name == secret.Name {
				affected = append(affected, iss)
				continue
			}
			// Match DNS-01 solver secrets so creating a missing solver Secret
			// re-queues the Issuer (see #9036).
			solverSecrets, err := acme.RequiredDNS01SolverSecrets(iss)
			if err != nil {
				// Don't let one issuer's conversion error stop every other
				// issuer from being matched against this Secret event.
				runtime.HandleError(fmt.Errorf("error determining ACME DNS-01 solver secrets for issuer %s/%s: %w", iss.Namespace, iss.Name, err))
				continue
			}
			for _, s := range solverSecrets {
				if s.Name == secret.Name {
					affected = append(affected, iss)
					break
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
			if iss.Spec.Venafi.NGTS != nil {
				if iss.Spec.Venafi.NGTS.CredentialsRef.Name == secret.Name {
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
