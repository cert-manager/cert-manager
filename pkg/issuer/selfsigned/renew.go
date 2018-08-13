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

package selfsigned

import (
	"context"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorRenewCert = "ErrRenewCert"

	successCertRenewed = "CertIssueSuccess"

	messageErrorRenewCert = "Error issuing TLS certificate: "

	messageCertRenewed = "Certificate issued successfully"
)

func (c *SelfSigned) Renew(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	signeeKey, err := kube.SecretTLSKey(c.secretsLister, crt.Namespace, crt.Spec.SecretName)

	if err != nil {
		s := messageErrorGetCertKeyPair + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorGetCertKeyPair, s, false)
		return nil, nil, err
	}

	certPem, err := c.obtainCertificate(crt, signeeKey)

	if err != nil {
		s := messageErrorRenewCert + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorRenewCert, s, false)
		return nil, nil, err
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertRenewed, messageCertRenewed, true)

	keyPem, err := pki.EncodePrivateKey(signeeKey)
	if err != nil {
		s := messageErrorEncodePrivateKey + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorEncodePrivateKey, s, false)
		return nil, nil, err
	}

	return keyPem, certPem, nil
}
