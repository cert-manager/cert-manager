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
	corelisters "k8s.io/client-go/listers/core/v1"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
)

// Vault Issuer for the certificate authority of Vault
type Vault struct {
	*controller.Context
	issuer v1.GenericIssuer

	secretsLister corelisters.SecretLister

	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace string
}

// NewVault returns a new Vault
func NewVault(ctx *controller.Context, issuer v1.GenericIssuer) (issuer.Interface, error) {
	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()

	return &Vault{
		Context:           ctx,
		issuer:            issuer,
		secretsLister:     secretsLister,
		resourceNamespace: ctx.IssuerOptions.ResourceNamespace(issuer),
	}, nil
}

// Register this Issuer with the issuer factory
func init() {
	issuer.RegisterIssuer(apiutil.IssuerVault, NewVault)
}
