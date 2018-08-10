/*
Copyright 2018 The Jetstack cert-manager contributors.

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

	"github.com/golang/glog"
	"k8s.io/api/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
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

func (c *CA) Setup(ctx context.Context) (issuer.SetupResponse, error) {
	cert, err := kube.SecretTLSCert(c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		s := messageErrorGetKeyPair + err.Error()
		glog.Info(s)
		c.Recorder.Event(c.issuer, v1.EventTypeWarning, errorGetKeyPair, s)
		c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorGetKeyPair, s)
		return issuer.SetupResponse{}, err
	}

	_, err = kube.SecretTLSKey(c.secretsLister, c.resourceNamespace, c.issuer.GetSpec().CA.SecretName)
	if err != nil {
		s := messageErrorGetKeyPair + err.Error()
		glog.Info(s)
		c.Recorder.Event(c.issuer, v1.EventTypeWarning, errorGetKeyPair, s)
		c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorGetKeyPair, s)
		return issuer.SetupResponse{}, err
	}

	if !cert.IsCA {
		s := messageErrorGetKeyPair + "certificate is not a CA"
		glog.Info(s)
		c.Recorder.Event(c.issuer, v1.EventTypeWarning, errorInvalidKeyPair, s)
		c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorInvalidKeyPair, s)
		// Don't return an error here as there is nothing more we can do
		return issuer.SetupResponse{}, nil
	}

	glog.Info(messageKeyPairVerified)
	c.Recorder.Event(c.issuer, v1.EventTypeNormal, successKeyPairVerified, messageKeyPairVerified)
	c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successKeyPairVerified, messageKeyPairVerified)

	return issuer.SetupResponse{}, nil
}
