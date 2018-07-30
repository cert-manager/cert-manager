package cfssl

import (
	"context"
	"fmt"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"k8s.io/api/core/v1"
)

const (
	errorCFSSL = "CFSSLError"

	successFieldsVerified = "FieldsVerified"

	messageConfigRequired          = "CFSSL config cannot be empty"
	messageServerAndPathRequired   = "CFSSL server and path are required fields"
	messageAuthKeyNameRequired     = "CFSSL authKey name is required"
	messageAuthKeyKeyRequired      = "CFSSL authKey key is required"
	messageAuthKeyKeyNotFound      = "CFSSL authKey must be provided"
	messageAuthKeyKeyInvalidFormat = "CFSSL authKey must be in hexadecimal format"
	messageFieldsVerified          = "Required Fields verified"
)

func (c *CFSSL) Setup(ctx context.Context) error {
	spec := c.issuer.GetSpec().CFSSL

	if spec == nil {
		glog.Infof("%s: %s", c.issuer.GetObjectMeta().Name, messageConfigRequired)
		c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorCFSSL, messageConfigRequired)
		return fmt.Errorf(messageConfigRequired)
	}

	if spec.AuthKey != nil {
		if spec.AuthKey.Name == "" {
			glog.Infof("%s: %s", c.issuer.GetObjectMeta().Name, messageAuthKeyNameRequired)
			c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorCFSSL, messageAuthKeyNameRequired)
			return fmt.Errorf(messageAuthKeyNameRequired)
		}

		if spec.AuthKey.Key == "" {
			glog.Infof("%s: %s", c.issuer.GetObjectMeta().Name, messageAuthKeyKeyRequired)
			c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorCFSSL, messageAuthKeyKeyRequired)
			return fmt.Errorf(messageAuthKeyKeyRequired)
		}
	}

	if spec.Server == "" || spec.Path == "" {
		glog.Infof("%s: %s", c.issuer.GetObjectMeta().Name, messageServerAndPathRequired)
		c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorCFSSL, messageServerAndPathRequired)
		return fmt.Errorf(messageServerAndPathRequired)
	}

	glog.Info(messageFieldsVerified)
	c.recorder.Event(c.issuer, v1.EventTypeNormal, successFieldsVerified, messageFieldsVerified)
	c.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successFieldsVerified, messageFieldsVerified)

	return nil
}
