package ca

import (
	"context"
	"fmt"

	"k8s.io/api/core/v1"

	"github.com/golang/glog"
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
	cert, err := kube.SecretTLSCert(c.secretsLister, c.issuerResourcesNamespace, c.issuer.GetSpec().CA.SecretName)

	if err != nil {
		s := messageErrorGetKeyPair + err.Error()
		glog.Info(s)
		c.recorder.Event(c.issuer, v1.EventTypeWarning, errorGetKeyPair, s)
		c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorGetKeyPair, s)
		return err
	}

	_, err = kube.SecretTLSKey(c.secretsLister, c.issuerResourcesNamespace, c.issuer.GetSpec().CA.SecretName)

	if err != nil {
		s := messageErrorGetKeyPair + err.Error()
		glog.Info(s)
		c.recorder.Event(c.issuer, v1.EventTypeWarning, errorGetKeyPair, s)
		c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorGetKeyPair, s)
		return err
	}

	if !cert.IsCA {
		s := messageErrorGetKeyPair + "certificate is not a CA"
		glog.Info(s)
		c.recorder.Event(c.issuer, v1.EventTypeWarning, errorInvalidKeyPair, s)
		c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorInvalidKeyPair, s)
		return fmt.Errorf(s)
	}

	glog.Info(messageKeyPairVerified)
	c.recorder.Event(c.issuer, v1.EventTypeNormal, successKeyPairVerified, messageKeyPairVerified)
	c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successKeyPairVerified, messageKeyPairVerified)

	return nil
}
