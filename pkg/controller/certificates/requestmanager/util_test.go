/*
Copyright 2020 The cert-manager Authors.

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

package requestmanager

import (
	"crypto"
	"crypto/x509"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

type cryptoBundle struct {
	// certificate is the Certificate resource used to create this bundle
	certificate *cmapi.Certificate
	// expectedRequestName is the name of the CertificateRequest that is
	// expected to be created to issue this certificate
	expectedRequestName string

	// privateKey is the private key used as the complement to the certificates
	// in this bundle
	privateKey      crypto.Signer
	privateKeyBytes []byte

	// csr is the CSR used to obtain the certificate in this bundle
	csr      *x509.CertificateRequest
	csrBytes []byte

	// certificateRequest is the request that is expected to be created to
	// obtain a certificate when using this bundle
	certificateRequest                     *cmapi.CertificateRequest
	certificateRequestReady                *cmapi.CertificateRequest
	certificateRequestFailed               *cmapi.CertificateRequest
	certificateRequestFailedInvalidRequest *cmapi.CertificateRequest

	// cert is a signed certificate
	cert      *x509.Certificate
	certBytes []byte
}

func mustCreateCryptoBundle(t *testing.T, crt *cmapi.Certificate) cryptoBundle {
	c, err := createCryptoBundle(crt)
	if err != nil {
		t.Fatalf("error generating crypto bundle: %v", err)
	}
	return *c
}

func createCryptoBundle(originalCert *cmapi.Certificate) (*cryptoBundle, error) {
	crt := originalCert.DeepCopy()
	if crt.Spec.PrivateKey == nil {
		crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}
	reqName, err := apiutil.ComputeName(crt.Name, crt.Spec)
	if err != nil {
		return nil, err
	}

	csrPEM, privateKey, err := gen.CSRForCertificate(crt)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, err := pki.EncodePrivateKey(privateKey, crt.Spec.PrivateKey.Encoding)
	if err != nil {
		return nil, err
	}

	csr, err := pki.DecodeX509CertificateRequestBytes(csrPEM)
	if err != nil {
		return nil, err
	}

	annotations := make(map[string]string)
	for k, v := range crt.Annotations {
		annotations[k] = v
	}

	annotations[cmapi.CertificateRequestRevisionAnnotationKey] = "NOT SET"
	annotations[cmapi.CertificateRequestPrivateKeyAnnotationKey] = crt.Spec.SecretName
	annotations[cmapi.CertificateNameKey] = crt.Name
	if crt.Status.NextPrivateKeySecretName != nil {
		annotations[cmapi.CertificateRequestPrivateKeyAnnotationKey] = *crt.Status.NextPrivateKeySecretName
	}
	certificateRequest := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "NOT SET",
			Namespace:       crt.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
			Annotations:     annotations,
		},
		Spec: cmapi.CertificateRequestSpec{
			Request:   csrPEM,
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			IsCA:      crt.Spec.IsCA,
		},
	}

	unsignedCert, err := pki.CertificateTemplateFromCertificateRequest(certificateRequest)
	if err != nil {
		return nil, err
	}

	certBytes, cert, err := pki.SignCertificate(unsignedCert, unsignedCert, privateKey.Public(), privateKey)
	if err != nil {
		return nil, err
	}

	certificateRequestReady := gen.CertificateRequestFrom(certificateRequest,
		gen.SetCertificateRequestCertificate(certBytes),
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:   cmapi.CertificateRequestConditionReady,
			Status: cmmeta.ConditionTrue,
			Reason: cmapi.CertificateRequestReasonIssued,
		}),
	)

	certificateRequestFailed := gen.CertificateRequestFrom(certificateRequest,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:   cmapi.CertificateRequestConditionReady,
			Status: cmmeta.ConditionFalse,
			Reason: cmapi.CertificateRequestReasonFailed,
		}),
	)

	certificateRequestFailedInvalidRequest := gen.CertificateRequestFrom(certificateRequestFailed,
		gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
			Type:   cmapi.CertificateRequestConditionInvalidRequest,
			Status: cmmeta.ConditionTrue,
			Reason: cmapi.CertificateRequestReasonFailed,
		}),
	)

	return &cryptoBundle{
		certificate:                            originalCert,
		expectedRequestName:                    reqName,
		privateKey:                             privateKey,
		privateKeyBytes:                        privateKeyBytes,
		csr:                                    csr,
		csrBytes:                               csrPEM,
		certificateRequest:                     certificateRequest,
		certificateRequestReady:                certificateRequestReady,
		certificateRequestFailed:               certificateRequestFailed,
		certificateRequestFailedInvalidRequest: certificateRequestFailedInvalidRequest,
		cert:                                   cert,
		certBytes:                              certBytes,
	}, nil
}
