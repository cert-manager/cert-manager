/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package venafi

import (
	corelisters "k8s.io/client-go/listers/core/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/internal/venafi"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

const (
	tppUsernameKey = "username"
	tppPasswordKey = "password"

	defaultAPIKeyKey = "api-key"
)

// Venafi is a implementation of govcert library to manager certificates from TPP or Venafi Cloud
type Venafi struct {
	issuer cmapi.GenericIssuer
	*controller.Context

	secretsLister corelisters.SecretLister

	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace string

	clientBuilder venafi.VenafiClientBuilder
}

func NewVenafi(ctx *controller.Context, issuer cmapi.GenericIssuer) (issuer.Interface, error) {
	return &Venafi{
		issuer:            issuer,
		secretsLister:     ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		resourceNamespace: ctx.IssuerOptions.ResourceNamespace(issuer),
		clientBuilder:     venafi.New,
		Context:           ctx,
	}, nil
}

func init() {
	issuer.RegisterIssuer(apiutil.IssuerVenafi, NewVenafi)
}
