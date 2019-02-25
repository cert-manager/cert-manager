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
	"k8s.io/klog"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
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
	cert, err := kube.SecretTLSCert(c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		s := messageErrorGetKeyPair + err.Error()
		klog.Info(s)
		c.Recorder.Event(c.issuer, v1.EventTypeWarning, errorGetKeyPair, s)
		apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorGetKeyPair, s)
		return err
	}

	_, err = kube.SecretTLSKey(c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		s := messageErrorGetKeyPair + err.Error()
		klog.Info(s)
		c.Recorder.Event(c.issuer, v1.EventTypeWarning, errorGetKeyPair, s)
		apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorGetKeyPair, s)
		return err
	}

	if !cert.IsCA {
		s := messageErrorGetKeyPair + "certificate is not a CA"
		klog.Info(s)
		c.Recorder.Event(c.issuer, v1.EventTypeWarning, errorInvalidKeyPair, s)
		apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorInvalidKeyPair, s)
		// Don't return an error here as there is nothing more we can do
		return nil
	}

	klog.Info(messageKeyPairVerified)
	c.Recorder.Event(c.issuer, v1.EventTypeNormal, successKeyPairVerified, messageKeyPairVerified)
	apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successKeyPairVerified, messageKeyPairVerified)

	return nil
}
