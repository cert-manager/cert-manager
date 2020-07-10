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

package ca

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
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

var _ issuers.IssuerBackend = &CA{}

// CA is a simple CA implementation backed by the Kubernetes API server.
// A secret resource is used to store a CA public and private key that is then
// used to sign certificates.
type CA struct {
	// Defines the issuer specific options set on the controller
	issuerOptions controllerpkg.IssuerOptions

	secretsLister corelisters.SecretLister
	recorder      record.EventRecorder
}

func New(ctx *controllerpkg.Context) issuers.IssuerBackend {
	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()

	return &CA{
		secretsLister: secretsLister,
		issuerOptions: ctx.IssuerOptions,
		recorder:      ctx.Recorder,
	}
}

func init() {
	issuers.RegisterIssuerBackend(IssuerControllerName, ClusterIssuerControllerName, New)
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

func (c *CA) TypeChecker(issuer cmapi.GenericIssuer) bool {
	return issuer.GetSpec().CA != nil
}

func (c *CA) SecretChecker(issuer cmapi.GenericIssuer, secret *corev1.Secret) bool {
	if caSpec := issuer.GetSpec().CA; caSpec != nil && caSpec.SecretName == secret.Name {
		return true
	}

	return false
}
