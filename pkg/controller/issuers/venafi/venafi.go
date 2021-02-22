/*
Copyright 2021 The cert-manager Authors.

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
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/issuers"
	"github.com/jetstack/cert-manager/pkg/internal/venafi"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	IssuerControllerName        = "IssuerVenafi"
	ClusterIssuerControllerName = "ClusterIssuerVenafi"

	errorPing   = "ErrorPing"
	errorClient = "ErrorClient"
)

var _ issuers.Issuer = &Venafi{}

// Venafi is a implementation of govcert library to manager certificates from TPP or Venafi Cloud
type Venafi struct {
	// Defines the issuer specific options set on the controller
	issuerOptions controllerpkg.IssuerOptions

	secretsLister corelisters.SecretLister
	clientBuilder venafi.VenafiClientBuilder
	recorder      record.EventRecorder
}

func New(ctx *controller.Context) issuers.Issuer {
	return &Venafi{
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		clientBuilder: venafi.New,
		recorder:      ctx.Recorder,
	}
}

func init() {
	// create issuer controller for venafi
	controllerpkg.Register(IssuerControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, IssuerControllerName).
			For(issuers.New(IssuerControllerName, cmapi.IssuerKind, New(ctx))).
			Complete()
	})

	// create cluster issuer controller for venafi
	controllerpkg.Register(ClusterIssuerControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ClusterIssuerControllerName).
			For(issuers.New(ClusterIssuerControllerName, cmapi.ClusterIssuerKind, New(ctx))).
			Complete()
	})
}

func (v *Venafi) Setup(ctx context.Context, issuer cmapi.GenericIssuer) (err error) {
	log := logf.FromContext(ctx, "setup").WithName(issuer.GetName())

	defer func() {
		if err != nil {
			errorMessage := "Failed to setup Venafi issuer"
			log.Error(err, errorMessage)
			apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, "ErrorSetup", fmt.Sprintf("%s: %v", errorMessage, err))
			err = fmt.Errorf("%s: %v", errorMessage, err)
		}
	}()

	resourceNamespace := v.issuerOptions.ResourceNamespace(issuer)
	client, err := v.clientBuilder(resourceNamespace, v.secretsLister, issuer)
	if err != nil {
		return fmt.Errorf("error building client: %v", err)
	}
	err = client.Ping()
	if err != nil {
		return fmt.Errorf("error pinging Venafi API: %v", err)
	}

	// If it does not already have a 'ready' condition, we'll also log an event
	// to make it really clear to users that this Issuer is ready.
	if !apiutil.IssuerHasCondition(issuer, cmapi.IssuerCondition{
		Type:   cmapi.IssuerConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		v.recorder.Eventf(issuer, corev1.EventTypeNormal, "Ready", "Verified issuer with Venafi server")
	}
	log.V(logf.DebugLevel).Info("Venafi issuer started")
	apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionTrue, "Venafi issuer started", "Venafi issuer started")

	return nil
}

func (v *Venafi) Implements(issuer cmapi.GenericIssuer) bool {
	return issuer.GetSpec().Venafi != nil
}

func (v *Venafi) ReferencesSecret(issuer cmapi.GenericIssuer, secret *corev1.Secret) bool {
	venafiSpec := issuer.GetSpec().Venafi
	if venafiSpec == nil {
		return false
	}

	if v.issuerOptions.ResourceNamespace(issuer) != secret.Namespace {
		return false
	}

	if venafiSpec.TPP != nil &&
		venafiSpec.TPP.CredentialsRef.Name == secret.Name {
		return true
	}

	if venafiSpec.Cloud != nil &&
		venafiSpec.Cloud.APITokenSecretRef.Name == secret.Name {
		return true
	}

	return false
}
