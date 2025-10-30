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
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	"github.com/cert-manager/cert-manager/pkg/issuer/venafi/client"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// CyberArk Certificate Manager is an implementation of govcert library to manager certificates from CyberArk Certificate Manager, Self-Hosted or SaaS
type Venafi struct {
	*controller.Context

	secretsLister internalinformers.SecretLister

	clientBuilder client.VenafiClientBuilder

	log logr.Logger

	// userAgent is the string used as the UserAgent when making HTTP calls.
	userAgent string
}

func NewVenafi(ctx *controller.Context) (issuer.Interface, error) {
	return &Venafi{
		secretsLister: ctx.KubeSharedInformerFactory.Secrets().Lister(),
		clientBuilder: client.New,
		Context:       ctx,
		log:           logf.Log.WithName("venafi"),
		userAgent:     ctx.RESTConfig.UserAgent,
	}, nil
}

func init() {
	issuer.RegisterIssuer(apiutil.IssuerVenafi, NewVenafi)
}
