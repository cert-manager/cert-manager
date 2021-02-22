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

package ca

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/issuers"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	utilkube "github.com/jetstack/cert-manager/pkg/util/kube"
)

const (
	IssuerControllerName        = "IssuerCA"
	ClusterIssuerControllerName = "ClusterIssuerCA"

	errorGetKeyPair     = "ErrGetKeyPair"
	errorInvalidKeyPair = "ErrInvalidKeyPair"

	successKeyPairVerified = "KeyPairVerified"

	messageErrorGetKeyPair     = "Error getting keypair for CA issuer: "
	messageErrorInvalidKeyPair = "Invalid signing key pair: "

	messageKeyPairVerified = "Signing CA verified"
)

var _ issuers.Issuer = &CA{}

// CA is a simple CA implementation backed by the Kubernetes API server.
// A secret resource is used to store a CA public and private key that is then
// used to sign certificates.
type CA struct {
	// Defines the issuer specific options set on the controller
	issuerOptions controllerpkg.IssuerOptions

	secretsLister corelisters.SecretLister
	recorder      record.EventRecorder
}

func New(ctx *controllerpkg.Context) issuers.Issuer {
	return &CA{
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		issuerOptions: ctx.IssuerOptions,
		recorder:      ctx.Recorder,
	}
}

func init() {
	// create issuer controller for ca
	controllerpkg.Register(IssuerControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, IssuerControllerName).
			For(issuers.New(IssuerControllerName, cmapi.IssuerKind, New(ctx))).
			Complete()
	})

	// create cluster issuer controller for ca
	controllerpkg.Register(ClusterIssuerControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ClusterIssuerControllerName).
			For(issuers.New(ClusterIssuerControllerName, cmapi.ClusterIssuerKind, New(ctx))).
			Complete()
	})
}

func (c *CA) Setup(ctx context.Context, issuer cmapi.GenericIssuer) error {
	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace := c.issuerOptions.ResourceNamespace(issuer)

	log := logf.FromContext(ctx, "setup").WithName(issuer.GetName())

	cert, err := utilkube.SecretTLSCert(ctx, c.secretsLister, resourceNamespace, issuer.GetSpec().CA.SecretName)
	if err != nil {
		log.Error(err, "error getting signing CA TLS certificate")
		s := messageErrorGetKeyPair + err.Error()
		c.recorder.Event(issuer, corev1.EventTypeWarning, errorGetKeyPair, s)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorGetKeyPair, s)
		return err
	}

	_, err = utilkube.SecretTLSKey(ctx, c.secretsLister, resourceNamespace, issuer.GetSpec().CA.SecretName)
	if err != nil {
		log.Error(err, "error getting signing CA private key")
		s := messageErrorGetKeyPair + err.Error()
		c.recorder.Event(issuer, corev1.EventTypeWarning, errorGetKeyPair, s)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorGetKeyPair, s)
		return err
	}

	log = logf.WithRelatedResourceName(log, issuer.GetSpec().CA.SecretName, resourceNamespace, "Secret")
	if !cert.IsCA {
		s := messageErrorGetKeyPair + "certificate is not a CA"
		log.Error(nil, "signing certificate is not a CA")
		c.recorder.Event(issuer, corev1.EventTypeWarning, errorInvalidKeyPair, s)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorInvalidKeyPair, s)
		// Don't return an error here as there is nothing more we can do
		return nil
	}

	log.Info("signing CA verified")
	c.recorder.Event(issuer, corev1.EventTypeNormal, successKeyPairVerified, messageKeyPairVerified)
	apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionTrue, successKeyPairVerified, messageKeyPairVerified)

	return nil
}

func (c *CA) Implements(issuer cmapi.GenericIssuer) bool {
	return issuer.GetSpec().CA != nil
}

func (c *CA) ReferencesSecret(issuer cmapi.GenericIssuer, secret *corev1.Secret) bool {
	caSpec := issuer.GetSpec().CA

	if caSpec == nil {
		return false
	}

	if c.issuerOptions.ResourceNamespace(issuer) == secret.Namespace &&
		caSpec.SecretName == secret.Name {
		return true
	}

	return false
}
