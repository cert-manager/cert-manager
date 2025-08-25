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

	core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	"github.com/cert-manager/cert-manager/pkg/util/kube"
)

// Acme is an issuer for an ACME server. It can be used to register and obtain
// certificates from any ACME server. It supports DNS01 and HTTP01 challenge
// mechanisms.
type Acme struct {
	secretsClient core.SecretsGetter
	recorder      record.EventRecorder

	// keyFromSecret returns a decoded account key from a Kubernetes secret.
	// It can be stubbed in unit tests.
	keyFromSecret keyFromSecretFunc

	// clientBuilder builds a new ACME client.
	clientBuilder accounts.NewClientFunc

	// namespace of referenced resources when the given issuer is a ClusterIssuer
	resourceNamespace func(iss cmapi.GenericIssuer) string
	// used as a cache for ACME clients
	accountRegistry accounts.Registry
}

// New returns a new ACME issuer interface for the given issuer.
func New(ctx *controller.Context) (issuer.Interface, error) {
	secretsLister := ctx.KubeSharedInformerFactory.Secrets().Lister()

	a := &Acme{
		keyFromSecret:     newKeyFromSecret(secretsLister),
		clientBuilder:     accounts.NewClient(ctx.Metrics, ctx.RESTConfig.UserAgent),
		secretsClient:     ctx.Client.CoreV1(),
		recorder:          ctx.Recorder,
		resourceNamespace: ctx.IssuerOptions.ResourceNamespace,
		accountRegistry:   ctx.ACMEAccountRegistry,
	}

	return a, nil
}

// keyFromSecretFunc accepts name, namespace and keyName for secret, verifies
// and returns a private key stored at keyName.
type keyFromSecretFunc func(ctx context.Context, namespace, name, keyName string) (crypto.Signer, error)

// newKeyFromSecret returns an implementation of keyFromSecretFunc for a secrets lister.
func newKeyFromSecret(secretLister internalinformers.SecretLister) keyFromSecretFunc {
	return func(ctx context.Context, namespace, name, keyName string) (crypto.Signer, error) {
		return kube.SecretTLSKeyRef(ctx, secretLister, namespace, name, keyName)
	}
}

// Register this Issuer with the issuer factory
func init() {
	issuer.RegisterIssuer(apiutil.IssuerACME, New)
}
