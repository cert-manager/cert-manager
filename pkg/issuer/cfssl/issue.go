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
	"encoding/json"
	"encoding/pem"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	reasonErrorPrivateKey = "ErrorPrivateKey"
	reasonErrorCA         = "ErrorCA"
	reasonErrorIssuerSpec = "ErrorIssuerSpec"
	reasonErrorSigning    = "ErrorSigning"
	reasonErrorCSR        = "ErrorCSR"
	reasonErrorCARequest  = "ErrorCARequest"
	reasonErrorInitIssuer = "ErrInitIssuer"

	messageAuthKeyFormat            = "error decoding auth key as hexadecimal"
	messageServerResponseNotSuccess = "server response not successful"
	messageServerResponseNon2xx     = "server returned a non 2xx response"
)

func (c *CFSSL) Issue(ctx context.Context, crt *v1alpha1.Certificate) (*issuer.IssueResponse, error) {
	// get a copy of the existing/currently issued Certificate's private key
	signeeKey, err := kube.SecretTLSKey(ctx, c.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		// if one does not already exist, generate a new one
		signeeKey, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorPrivateKey, "Error generating certificate private key: %v", err)
			// don't trigger a retry. An error from this function implies some
			// invalid input parameters, and retrying without updating the
			// resource will not help.
			return nil, nil
		}
	}

	if err != nil {
		klog.Errorf("Error getting private key %q for certificate: %v", crt.Spec.SecretName, err)
		return nil, err
	}

	// generate a x509 certificate request template for this Certificate
	template, err := pki.GenerateCSR(c.issuer, crt)
	if err != nil {
		return nil, err
	}

	csrBytes, err := pki.EncodeCSR(template, signeeKey)
	if err != nil {
		return nil, err
	}

	block := pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}
	request := signRequest{CertificateRequest: string(pem.EncodeToMemory(&block))}
	if crt.Spec.CFSSL != nil {
		request.Profile = crt.Spec.CFSSL.Profile
		request.Label = crt.Spec.CFSSL.Label
	}

	data, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("Error json marshalling request: %v", err)
	}

	cert, err := c.client.Sign(data)
	if err != nil {
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorSigning, "Failed to request certificate from remote: %v", err)
		return nil, fmt.Errorf("Error signing csr: %v", err)
	}

	// Fetch CA Certificate
	infoResp, err := c.client.Info([]byte(`{}`))
	if err != nil {
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorSigning, "Failed to request CA certificate from remote: %v", err)
		return nil, fmt.Errorf("Error requesting issuer CA certitifate: %v", err)
	}
	caCert := []byte(infoResp.Certificate)

	// Encode output private key and CA cert ready for return
	keyPem, err := pki.EncodePrivateKey(signeeKey)
	if err != nil {
		c.Recorder.Eventf(crt, corev1.EventTypeWarning, reasonErrorPrivateKey, "Error encoding private key: %v", err)
		return nil, err
	}

	return &issuer.IssueResponse{
		PrivateKey:  keyPem,
		Certificate: cert,
		CA:          caCert,
	}, nil
}
