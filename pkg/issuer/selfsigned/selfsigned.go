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

package selfsigned

import (
	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
)

// SelfSigned is an Issuer implementation the simply self-signs Certificates.
// For more info see: https://cert-manager.io/docs/configuration/selfsigned/
type SelfSigned struct {
	*controller.Context
	issuer v1.GenericIssuer

	secretsLister internalinformers.SecretLister
}

func NewSelfSigned(ctx *controller.Context, issuer v1.GenericIssuer) (issuer.Interface, error) {
	secretsLister := ctx.KubeSharedInformerFactory.Secrets().Lister()

	return &SelfSigned{
		Context:       ctx,
		issuer:        issuer,
		secretsLister: secretsLister,
	}, nil
}

func init() {
	issuer.RegisterIssuer(apiutil.IssuerSelfSigned, NewSelfSigned)
}
