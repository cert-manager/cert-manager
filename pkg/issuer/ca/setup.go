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
	"context"

	corev1 "k8s.io/api/core/v1"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/pkg/util/kube"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

const (
	errorGetKeyPair     = "ErrGetKeyPair"
	errorInvalidKeyPair = "ErrInvalidKeyPair"
	errorMLDSADisabled  = "MLDSAPrivateKeysDisabled"

	successKeyPairVerified = "KeyPairVerified"

	messageErrorGetKeyPair = "Error getting keypair for CA issuer: "
	messageMLDSADisabled   = "Signing CA has an ML-DSA key, which requires the MLDSAPrivateKeys feature gate to be enabled"

	messageKeyPairVerified = "Signing CA verified"
)

// Setup verifies signing CA.
func (c *CA) Setup(ctx context.Context, issuer v1.GenericIssuer) error {
	log := logf.FromContext(ctx, "setup")

	resourceNamespace := c.ResourceNamespace(issuer)

	cert, err := kube.SecretTLSCert(ctx, c.secretsLister, resourceNamespace, issuer.GetSpec().CA.SecretName)
	if err != nil {
		log.Error(err, "error getting signing CA TLS certificate")
		s := messageErrorGetKeyPair + err.Error()
		c.Recorder.Event(issuer, corev1.EventTypeWarning, errorGetKeyPair, s)
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorGetKeyPair, s)
		return err
	}

	key, err := kube.SecretTLSKey(ctx, c.secretsLister, resourceNamespace, issuer.GetSpec().CA.SecretName)
	if err != nil {
		log.Error(err, "error getting signing CA private key")
		s := messageErrorGetKeyPair + err.Error()
		c.Recorder.Event(issuer, corev1.EventTypeWarning, errorGetKeyPair, s)
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorGetKeyPair, s)
		return err
	}

	log = logf.WithRelatedResourceName(log, issuer.GetSpec().CA.SecretName, resourceNamespace, "Secret")
	if !cert.IsCA {
		s := messageErrorGetKeyPair + "certificate is not a CA"
		log.Error(err, "signing certificate is not a CA")
		c.Recorder.Event(issuer, corev1.EventTypeWarning, errorInvalidKeyPair, s)
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorInvalidKeyPair, s)
		// Don't return an error here as there is nothing more we can do
		return nil
	}

	if !utilfeature.DefaultFeatureGate.Enabled(feature.MLDSAPrivateKeys) && pki.IsMLDSAPublicKey(key.Public()) {
		log.Error(nil, "signing CA has an ML-DSA key but the MLDSAPrivateKeys feature gate is disabled")
		c.Recorder.Event(issuer, corev1.EventTypeWarning, errorMLDSADisabled, messageMLDSADisabled)
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorMLDSADisabled, messageMLDSADisabled)
		// Don't return an error here: changing the feature gate restarts the
		// controller, which resyncs every issuer.
		return nil
	}

	log.V(logf.DebugLevel).Info("signing CA verified")
	c.Recorder.Event(issuer, corev1.EventTypeNormal, successKeyPairVerified, messageKeyPairVerified)
	apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionTrue, successKeyPairVerified, messageKeyPairVerified)

	return nil
}
