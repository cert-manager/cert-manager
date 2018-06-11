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

package cfssl

import (
	"context"

	"k8s.io/klog"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	errorIssuerConfig = "ErrIssuerConfig"

	successFieldsVerified = "FieldsVerified"

	messageIssuerConfig            = "Invalid config for CFSSL issuer: "
	messageConfigRequired          = "CFSSL issuer config cannot be empty"
	messageServerRequired          = "CFSSL server is required"
	messageAuthKeyNameRequired     = "CFSSL authKey name is required"
	messageAuthKeyKeyRequired      = "CFSSL authKey key is required"
	messageAuthKeyKeyNotFound      = "CFSSL authKey must be provided"
	messageAuthKeyKeyInvalidFormat = "CFSSL authKey must be in hexadecimal format"
	messageFieldsVerified          = "Required Fields verified"
)

func (c *CFSSL) Setup(ctx context.Context) error {
	spec := c.issuer.GetSpec().CFSSL

	if spec == nil {
		klog.Infof("%s: %s", c.issuer.GetObjectMeta().Name, messageConfigRequired)
		apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorIssuerConfig, messageConfigRequired)
		return nil
	}

	if spec.AuthKey != nil {
		if spec.AuthKey.Name == "" {
			klog.Infof("%s: %s", c.issuer.GetObjectMeta().Name, messageAuthKeyNameRequired)
			apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorIssuerConfig, messageAuthKeyNameRequired)
			return nil
		}

		if spec.AuthKey.Key == "" {
			klog.Infof("%s: %s", c.issuer.GetObjectMeta().Name, messageAuthKeyKeyRequired)
			klog.Info(messageAuthKeyKeyRequired)
			apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorIssuerConfig, messageAuthKeyKeyRequired)
			return nil
		}
	}

	if spec.Server == "" {
		klog.Infof("%s: %s", c.issuer.GetObjectMeta().Name, messageServerRequired)
		apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorIssuerConfig, messageServerRequired)
		return nil
	}

	klog.Info(messageFieldsVerified)
	apiutil.SetIssuerCondition(c.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successFieldsVerified, messageFieldsVerified)

	return nil
}
