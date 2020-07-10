/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
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

var _ issuers.IssuerBackend = &Venafi{}

// Venafi is a implementation of govcert library to manager certificates from TPP or Venafi Cloud
type Venafi struct {
	// Defines the issuer specific options set on the controller
	issuerOptions controllerpkg.IssuerOptions

	secretsLister corelisters.SecretLister
	clientBuilder venafi.VenafiClientBuilder
	recorder      record.EventRecorder
}

func New(ctx *controller.Context) issuers.IssuerBackend {
	return &Venafi{
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		clientBuilder: venafi.New,
		recorder:      ctx.Recorder,
	}
}

func init() {
	issuers.RegisterIssuerBackend(IssuerControllerName, ClusterIssuerControllerName, New)
}

func (v *Venafi) Setup(ctx context.Context, issuer cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx, "setup").WithName(issuer.GetName())

	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace := v.issuerOptions.ResourceNamespace(issuer)

	client, err := v.clientBuilder(resourceNamespace, v.secretsLister, issuer)
	if err != nil {
		log.Error(err, "failed to build client")
		v.recorder.Event(issuer, corev1.EventTypeWarning, errorClient, err.Error())

		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse,
			errorClient, fmt.Sprintf("Failed to build Venafi client: %s", err))

		return err
	}

	if err := client.Ping(); err != nil {
		log.Error(err, "Issuer could not connect to endpoint with provided credentials. Issuer failed to connect to endpoint\n")
		v.recorder.Event(issuer, corev1.EventTypeWarning, errorPing, err.Error())

		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse,
			errorPing, fmt.Sprintf("Failed to connect to Venafi endpoint: %s", err))

		return fmt.Errorf("error verifying Venafi client: %s", err)
	}

	log.Info("Venafi issuer started")
	v.recorder.Eventf(issuer, corev1.EventTypeNormal, "Ready", "Verified issuer with Venafi server")
	apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionTrue, "Venafi issuer started", "Venafi issuer started")

	return nil
}

func (v *Venafi) TypeChecker(issuer cmapi.GenericIssuer) bool {
	return issuer.GetSpec().Venafi != nil
}

func (v *Venafi) SecretChecker(issuer cmapi.GenericIssuer, secret *corev1.Secret) bool {
	venafiSpec := issuer.GetSpec().Venafi
	if venafiSpec == nil {
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
