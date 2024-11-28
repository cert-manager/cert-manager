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

package issuerlib

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

type ct struct {
	issuerLister              cmlisters.IssuerLister
	kubeSharedInformerFactory internalinformers.KubeInformerFactory
}

var _ source.TypedSource[reconcile.Request] = &ct{}

func (c *ct) Start(ctx context.Context, wq workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
	log := logf.FromContext(ctx)
	secretInformer := c.kubeSharedInformerFactory.Secrets()

	// register handler functions
	if _, err := secretInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: func(obj interface{}) {
		log := log.WithName("secretEvent")
		secret, ok := controllerpkg.ToSecret(obj)
		if !ok {
			log.Error(nil, "object is not a secret", "object", obj)
			return
		}

		log = logf.WithResource(log, secret)
		issuers, err := c.issuersForSecret(secret)
		if err != nil {
			log.Error(err, "error looking up issuers observing secret")
			return
		}
		for _, iss := range issuers {
			wq.Add(reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      iss.Name,
					Namespace: iss.Namespace,
				},
			})
		}
	}}); err != nil {
		return fmt.Errorf("error setting up event handler: %v", err)
	}

	return nil
}

func (c *ct) issuersForSecret(secret *corev1.Secret) ([]*v1.Issuer, error) {
	issuers, err := c.issuerLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing issuers: %s", err.Error())
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
