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

	core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	"github.com/cert-manager/cert-manager/pkg/metrics"
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
	clusterResourceNamespace string
	// used as a cache for ACME clients
	accountRegistry accounts.Registry

	// metrics is used to create instrumented ACME clients
	metrics *metrics.Metrics

	// userAgent is the string used as the UserAgent when making HTTP calls.
	userAgent string

	// controller-runtime client
	ctrlclient ctrlclient.Client

	// registrationFieldManager is a unique field manager used to update the status of the issuer
	// with ACME registration data.
	registrationFieldManager string

	// applyACMEStatus can be overwritten for testing
	applyACMEStatus func(ctx context.Context, ctrlclient ctrlclient.Client, fieldManager string, issuer cmapi.GenericIssuer, acmeStatus *cmacme.ACMEIssuerStatus) error
}

// New returns a new ACME issuer interface for the given issuer.
func New(ctx *controller.Context, issuer cmapi.GenericIssuer) (issuer.Interface, error) {
	if issuer.GetSpec().ACME == nil {
		return nil, fmt.Errorf("acme config may not be empty")
	}

	secretsLister := ctx.KubeSharedInformerFactory.Secrets().Lister()

	crClient, err := ctrlclient.New(ctx.RESTConfig, ctrlclient.Options{
		Scheme: ctx.Scheme,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create controller-runtime client: %v", err)
	}

	a := &Acme{
		keyFromSecret: newKeyFromSecret(secretsLister),
		clientBuilder: func(options accounts.NewClientOptions) acmecl.Interface {
			return accounts.NewClient(ctx.Metrics, ctx.RESTConfig.UserAgent, options)
		},
		secretsClient:            ctx.Client.CoreV1(),
		recorder:                 ctx.Recorder,
		clusterResourceNamespace: ctx.IssuerOptions.ClusterResourceNamespace,
		accountRegistry:          ctx.ACMEOptions.AccountRegistry,
		metrics:                  ctx.Metrics,
		userAgent:                ctx.RESTConfig.UserAgent,

		ctrlclient:               crClient,
		registrationFieldManager: fmt.Sprintf("%s/acme-registration", ctx.FieldManager),

		applyACMEStatus: applyACMEStatus,
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
