/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package acme

import (
	"fmt"

	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/utils/clock"

	"github.com/jetstack/cert-manager/pkg/acme"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmacmelisters "github.com/jetstack/cert-manager/pkg/client/listers/acme/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

// Acme is an issuer for an ACME server. It can be used to register and obtain
// certificates from any ACME server. It supports DNS01 and HTTP01 challenge
// mechanisms.
type Acme struct {
	*controller.Context
	issuer v1alpha2.GenericIssuer
	helper acme.Helper

	secretsLister corelisters.SecretLister
	orderLister   cmacmelisters.OrderLister

	// used for testing
	clock clock.Clock
}

// New returns a new ACME issuer interface for the given issuer.
func New(ctx *controller.Context, issuer v1alpha2.GenericIssuer) (issuer.Interface, error) {
	if issuer.GetSpec().ACME == nil {
		return nil, fmt.Errorf("acme config may not be empty")
	}

	// TODO: invent a way to ensure WaitForCacheSync is called for all listers
	// we are interested in

	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()
	orderLister := ctx.SharedInformerFactory.Acme().V1alpha2().Orders().Lister()

	a := &Acme{
		Context: ctx,
		helper:  acme.NewHelper(secretsLister, ctx.ClusterResourceNamespace),
		issuer:  issuer,

		secretsLister: secretsLister,
		orderLister:   orderLister,
		clock:         clock.RealClock{},
	}

	return a, nil
}

// Register this Issuer with the issuer factory
func init() {
	issuer.RegisterIssuer(apiutil.IssuerACME, New)
}
