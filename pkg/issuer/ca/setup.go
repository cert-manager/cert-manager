package ca

import (
	"context"
	"fmt"

	"k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/golang/glog"
	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/util/kube"
)

const (
	errorGetKeyPair     = "ErrGetKeyPair"
	errorInvalidKeyPair = "ErrInvalidKeyPair"

	successKeyPairVerified = "KeyPairVerified"

	messageErrorGetKeyPair     = "Error getting keypair for CA issuer: "
	messageErrorInvalidKeyPair = "Invalid signing key pair: "

	messageKeyPairVerified = "Signing CA verified"
)

func (c *CA) Setup(ctx context.Context) (v1alpha1.IssuerStatus, error) {
	update := c.issuer.Copy()

	cert, err := kube.SecretTLSCert(c.secretsLister, c.resourceNamespace, update.GetSpec().CA.SecretName)

	if k8sErrors.IsNotFound(err) {
		s := messageErrorGetKeyPair + err.Error()
		glog.Info(s)
		c.recorder.Event(update, v1.EventTypeWarning, errorGetKeyPair, s)
		update.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorGetKeyPair, s)
		return *update.GetStatus(), err
	}

	if !cert.IsCA {
		s := messageErrorGetKeyPair + "certificate is not a CA"
		glog.Info(s)
		c.recorder.Event(update, v1.EventTypeWarning, errorInvalidKeyPair, s)
		update.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorInvalidKeyPair, s)
		return *update.GetStatus(), fmt.Errorf(s)
	}

	glog.Info(messageKeyPairVerified)
	c.recorder.Event(update, v1.EventTypeNormal, successKeyPairVerified, messageKeyPairVerified)
	update.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successKeyPairVerified, messageKeyPairVerified)

	return *update.GetStatus(), nil
}
