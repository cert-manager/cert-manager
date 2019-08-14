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

package vault

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	vaultinternal "github.com/jetstack/cert-manager/pkg/internal/vault"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorGetCertKeyPair = "ErrGetCertKeyPair"
	errorIssueCert      = "ErrIssueCert"

	successCertIssued = "CertIssueSuccess"

	messageErrorIssueCert = "Error issuing TLS certificate: "

	messageCertIssued = "Certificate issued successfully"
)

func (v *Vault) Issue(ctx context.Context, crt *v1alpha1.Certificate) (*issuer.IssueResponse, error) {
	// get a copy of the existing/currently issued Certificate's private key
	signeePrivateKey, err := kube.SecretTLSKey(ctx, v.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		// if one does not already exist, generate a new one
		signeePrivateKey, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			v.Recorder.Eventf(crt, corev1.EventTypeWarning, "PrivateKeyError", "Error generating certificate private key: %v", err)
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

	/// BEGIN building CSR
	// TODO: we should probably surface some of these errors to users
	template, err := pki.GenerateCSR(crt)
	if err != nil {
		return nil, err
	}
	derBytes, err := pki.EncodeCSR(template, signeePrivateKey)
	if err != nil {
		return nil, err
	}
	pemRequestBuf := &bytes.Buffer{}
	err = pem.Encode(pemRequestBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes})
	if err != nil {
		return nil, fmt.Errorf("error encoding certificate request: %s", err.Error())
	}
	/// END building CSR

	/// BEGIN requesting certificate
	certDuration := apiutil.DefaultCertDuration(crt.Spec.Duration)

	vaultClient, err := vaultinternal.New(v.resourceNamespace, v.secretsLister, v.issuer)
	if err != nil {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "VaultInitError", "Error initialising vault client: %s", err)
		return nil, nil
	}

	certPem, caPem, err := vaultClient.Sign(pemRequestBuf.Bytes(), certDuration)
	if err != nil {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Failed to request certificate: %v", err)
		return nil, err
	}
	/// END requesting certificate

	key, err := pki.EncodePrivateKey(signeePrivateKey, crt.Spec.KeyEncoding)
	if err != nil {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorPrivateKey", "Error encoding private key: %v", err)
		return nil, err
	}

	return &issuer.IssueResponse{
		PrivateKey:  key,
		Certificate: certPem,
		CA:          caPem,
	}, nil
}
