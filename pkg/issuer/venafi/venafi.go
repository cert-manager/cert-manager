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

package venafi

import (
	"github.com/go-logr/logr"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	"github.com/cert-manager/cert-manager/pkg/issuer/venafi/client"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// Venafi is an implementation of govcert library to manager certificates from TPP or Venafi Cloud
type Venafi struct {
	issuer cmapi.GenericIssuer
	*controller.Context

	secretsLister internalinformers.SecretLister

	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace string

	clientBuilder client.VenafiClientBuilder

	log logr.Logger

	// userAgent is the string used as the UserAgent when making HTTP calls.
	userAgent string
}

func NewVenafi(ctx *controller.Context, issuer cmapi.GenericIssuer) (issuer.Interface, error) {
	return &Venafi{
		issuer:            issuer,
		secretsLister:     ctx.KubeSharedInformerFactory.Secrets().Lister(),
		resourceNamespace: ctx.IssuerOptions.ResourceNamespace(issuer),
		clientBuilder:     client.New,
		Context:           ctx,
		log:               logf.Log.WithName("venafi"),
		userAgent:         ctx.RESTConfig.UserAgent,
	}, nil
}

func init() {
	issuer.RegisterIssuer(apiutil.IssuerVenafi, NewVenafi)
}
