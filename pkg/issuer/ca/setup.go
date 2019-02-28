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

	"k8s.io/api/core/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/kube"
)

const (
	errorGetKeyPair     = "ErrGetKeyPair"
	errorInvalidKeyPair = "ErrInvalidKeyPair"

	successKeyPairVerified = "KeyPairVerified"

	messageErrorGetKeyPair     = "Error getting keypair for CA issuer: "
	messageErrorInvalidKeyPair = "Invalid signing key pair: "

	messageKeyPairVerified = "Signing CA verified"
)

func (c *CA) Setup(ctx context.Context) error {
	log := logf.FromContext(ctx, "setup")

	cert, err := kube.SecretTLSCert(ctx, c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		log.Error(err, "error getting signing CA TLS certificate")
		s := messageErrorGetKeyPair + err.Error()
		c.Recorder.Event(c.issuer, v1.EventTypeWarning, errorGetKeyPair, s)
		apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorGetKeyPair, s)
		return err
	}

	_, err = kube.SecretTLSKey(ctx, c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		log.Error(err, "error getting signing CA private key")
		s := messageErrorGetKeyPair + err.Error()
		c.Recorder.Event(c.issuer, v1.EventTypeWarning, errorGetKeyPair, s)
		apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorGetKeyPair, s)
		return err
	}

	log = logf.WithRelatedResourceName(log, c.issuer.GetSpec().CA.SecretName, c.resourceNamespace, "Secret")
	if !cert.IsCA {
		s := messageErrorGetKeyPair + "certificate is not a CA"
		log.Error(nil, "signing certificate is not a CA")
		c.Recorder.Event(c.issuer, v1.EventTypeWarning, errorInvalidKeyPair, s)
		apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorInvalidKeyPair, s)
		// Don't return an error here as there is nothing more we can do
		return nil
	}

	log.Info("signing CA verified")
	c.Recorder.Event(c.issuer, v1.EventTypeNormal, successKeyPairVerified, messageKeyPairVerified)
	apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successKeyPairVerified, messageKeyPairVerified)

	return nil
}
