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

package vault

import (
	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	vaultinternal "github.com/cert-manager/cert-manager/internal/vault"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
)

// Vault Issuer for the certificate authority of Vault
type Vault struct {
	*controller.Context

	secretsLister internalinformers.SecretLister

	// For testing purposes.
	createTokenFn func(ns string) vaultinternal.CreateToken
}

// NewVault returns a new Vault
func NewVault(ctx *controller.Context) (issuer.Interface, error) {
	secretsLister := ctx.KubeSharedInformerFactory.Secrets().Lister()

	return &Vault{
		Context:       ctx,
		secretsLister: secretsLister,
		createTokenFn: func(ns string) vaultinternal.CreateToken { return ctx.Client.CoreV1().ServiceAccounts(ns).CreateToken },
	}, nil
}

// Register this Issuer with the issuer factory
func init() {
	issuer.RegisterIssuer(apiutil.IssuerVault, NewVault)
}
