/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package client

import (
	"context"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
)

// Builder is any constructor function capable of building a venaficlient using
// only the configuration available in GenericIssuer
type Builder func(ctx context.Context, issuer cmapi.GenericIssuer) (Interface, error)

// BuilderFromSecretClients returns closer (Builder) that uses the supplied
// secret lister and core client to construct the namespaced Secret getter and
// setter used by secretStore.
func BuilderFromSecretClients(secretLister corelisters.SecretLister, coreClient coreclient.CoreV1Interface, issuerOptions controllerpkg.IssuerOptions) Builder {
	return func(ctx context.Context, issuer cmapi.GenericIssuer) (Interface, error) {
		cfg := issuer.GetSpec().Venafi
		namespace := issuerOptions.ResourceNamespace(issuer)
		return New(
			cfg,
			NewSecretStore(
				cfg,
				secretLister.Secrets(namespace),
				coreClient.Secrets(namespace),
			),
		)
	}
}
