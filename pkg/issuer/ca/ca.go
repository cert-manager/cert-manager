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

package ca

import (
	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
)

// CA is a simple CA implementation backed by the Kubernetes API server.
// A secret resource is used to store a CA public and private key that is then
// used to sign certificates.
type CA struct {
	*controller.Context
	secretsLister internalinformers.SecretLister
}

func NewCA(ctx *controller.Context) (issuer.Interface, error) {
	secretsLister := ctx.KubeSharedInformerFactory.Secrets().Lister()

	return &CA{
		Context:       ctx,
		secretsLister: secretsLister,
	}, nil
}

func init() {
	issuer.RegisterIssuer(apiutil.IssuerCA, NewCA)
}
