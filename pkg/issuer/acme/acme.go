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

package acme

import (
	"context"
	"crypto"
	"fmt"

	networkingv1beta1 "k8s.io/api/networking/v1"
	core "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	netlisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/record"

	"github.com/jetstack/cert-manager/internal/ingress"
	"github.com/jetstack/cert-manager/pkg/acme/accounts"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/util/kube"
)

// Acme is an issuer for an ACME server. It can be used to register and obtain
// certificates from any ACME server. It supports DNS01 and HTTP01 challenge
// mechanisms.
type Acme struct {
	issuer v1.GenericIssuer

	secretsClient core.SecretsGetter
	recorder      record.EventRecorder

	// keyFromSecret returns a decoded account key from a Kubernetes secret.
	// It can be stubbed in unit tests.
	keyFromSecret keyFromSecretFunc

	// clientBuilder builds a new ACME client.
	clientBuilder accounts.NewClientFunc

	// ingressClassLister is used to list ingress classes.
	ingressClassLister netlisters.IngressClassLister

	// cert-manager may start either in "Ingress v1beta1" ("old" ingress) or
	// "Ingress v1" ("new" ingress) mode.
	usesOldV1beta1Ingress bool

	// namespace of referenced resources when the given issuer is a ClusterIssuer
	clusterResourceNamespace string
	// used as a cache for ACME clients
	accountRegistry accounts.Registry

	// metrics is used to create instrumented ACME clients
	metrics *metrics.Metrics
}

// New returns a new ACME issuer interface for the given issuer.
func New(ctx *controller.Context, issuer v1.GenericIssuer) (issuer.Interface, error) {
	if issuer.GetSpec().ACME == nil {
		return nil, fmt.Errorf("acme config may not be empty")
	}

	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()
	ingressClassLister := ctx.KubeSharedInformerFactory.Networking().V1().IngressClasses().Lister()

	a := &Acme{
		issuer:                   issuer,
		keyFromSecret:            newKeyFromSecret(secretsLister),
		clientBuilder:            accounts.NewClient,
		secretsClient:            ctx.Client.CoreV1(),
		ingressClassLister:       ingressClassLister,
		usesOldV1beta1Ingress:    ingress.HasVersion(ctx.DiscoveryClient, networkingv1beta1.SchemeGroupVersion.String()),
		recorder:                 ctx.Recorder,
		clusterResourceNamespace: ctx.IssuerOptions.ClusterResourceNamespace,
		accountRegistry:          ctx.ACMEOptions.AccountRegistry,
		metrics:                  ctx.Metrics,
	}

	return a, nil
}

// keyFromSecretFunc accepts name, namespace and keyName for secret, verifies
// and returns a private key stored at keyName.
type keyFromSecretFunc func(ctx context.Context, namespace, name, keyName string) (crypto.Signer, error)

// newKeyFromSecret returns an implementation of keyFromSecretFunc for a secrets lister.
func newKeyFromSecret(secretLister corelisters.SecretLister) keyFromSecretFunc {
	return func(ctx context.Context, namespace, name, keyName string) (crypto.Signer, error) {
		return kube.SecretTLSKeyRef(ctx, secretLister, namespace, name, keyName)
	}
}

// Register this Issuer with the issuer factory
func init() {
	issuer.RegisterIssuer(apiutil.IssuerACME, New)
}
