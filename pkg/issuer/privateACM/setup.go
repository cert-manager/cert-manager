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

package privateACM

import (
	"context"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"k8s.io/klog"
)

const (
	errorPrivateACM                 = "PrivateACMError"
	messageAccessKeyIDRequired      = "Access Key ID cannot be empty"
	messageSecretAccessKey          = "Secret Access Key cannot be empty"
	messagePrivateACMConfigRequired = "Private ACM config cannot be empty"
	messageCertAuthorityARNRequired = "Certificate Authority ARN cannot be empty"
	messageRegionRequired           = "Region cannot be empty"
	successPrivateACMVerified       = "KeyPairVerified"
	messagePrivateACMVerified       = "Private ACM Verified"
)

func (acm *PrivateACM) Setup(ctx context.Context) error {
	if acm.issuer.GetSpec().PrivateACM == nil {
		klog.Infof("%s: %s", acm.issuer.GetObjectMeta().Name, messagePrivateACMConfigRequired)
		apiutil.SetIssuerCondition(acm.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorPrivateACM, messagePrivateACMConfigRequired)
		return nil
	}

	if acm.issuer.GetSpec().PrivateACM.AccessKeyIDRef.Name == "" {
		klog.Infof("%s: %s", acm.issuer.GetObjectMeta().Name, messageAccessKeyIDRequired)
		apiutil.SetIssuerCondition(acm.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorPrivateACM, messageAccessKeyIDRequired)
		return nil
	}
	if acm.issuer.GetSpec().PrivateACM.SecretAccessKeyRef.Name == "" {
		klog.Infof("%s: %s", acm.issuer.GetObjectMeta().Name, messageSecretAccessKey)
		apiutil.SetIssuerCondition(acm.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorPrivateACM, messageSecretAccessKey)
		return nil
	}

	if acm.issuer.GetSpec().PrivateACM.CertificateAuthorityARN == "" {
		klog.Infof("%s: %s", acm.issuer.GetObjectMeta().Name, messageCertAuthorityARNRequired)
		apiutil.SetIssuerCondition(acm.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorPrivateACM, messageCertAuthorityARNRequired)
		return nil
	}

	if acm.issuer.GetSpec().PrivateACM.Region == "" {
		klog.Infof("%s: %s", acm.issuer.GetObjectMeta().Name, messageRegionRequired)
		apiutil.SetIssuerCondition(acm.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorPrivateACM, messageRegionRequired)
		return nil
	}

	klog.Info(successPrivateACMVerified)
	apiutil.SetIssuerCondition(acm.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successPrivateACMVerified, messagePrivateACMVerified)
	return nil
}
