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

package certificates

import (
	"context"
	"encoding/pem"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

// ensureConditionNotApplied ensures that the provided condition is *not* applied to the certificate within 2 seconds.
func ensureConditionNotApplied(ctx context.Context, t *testing.T, cmCl cmclient.Interface, cert *cmapi.Certificate, condition cmapi.CertificateCondition) {
	err := wait.Poll(time.Millisecond*200, time.Second*2, func() (done bool, err error) {
		c, err := cmCl.CertmanagerV1().Certificates(cert.Namespace).Get(ctx, cert.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if apiutil.CertificateHasCondition(c, condition) {
			return true, nil
		}
		return false, nil
	})
	switch {
	case err == nil:
		// condition was applied
		t.Fatalf("expected Certificate to not have %v condition set to %v", condition.Type, condition.Status)
	case err == wait.ErrWaitTimeout:
		// success- condition has not been applied
	default:
		// some other erorr
		t.Fatal(err)
	}
}

// ensureConditionApplied ensures that a condition gets applied to a Certificate (within 5 seconds).
// and once the condition has been applied, also runs any provided additional assertions.
func ensureConditionApplied(ctx context.Context, t *testing.T, cmCl cmclient.Interface, cert *cmapi.Certificate, condition cmapi.CertificateCondition, assertions ...assertFunc) {
	err := wait.Poll(time.Millisecond*100, time.Second*5, func() (done bool, err error) {
		c, err := cmCl.CertmanagerV1().Certificates(cert.Namespace).Get(ctx, cert.Name, metav1.GetOptions{})
		if err != nil {
			// certificate not found
			return false, err
		}
		if !apiutil.CertificateHasCondition(c, condition) {
			t.Logf("Certificate does not have the expected %v conditon: %v, retrying", condition.Type, condition.Status)
			return false, nil
		}
		//condition has been applied, run addition assertions
		for _, a := range assertions {
			a(t, c)
		}
		return true, nil
	})
	if err != nil {
		t.Logf("expected Certificate to have %v condition set to %v", condition.Type, condition.Status)
		t.Fatal(err)
	}
}

type assertFunc func(*testing.T, *cmapi.Certificate)

// mustGenerateCSRImpl returns PEM encoded certificate signing request.
func mustGenerateCSRImpl(t *testing.T, pkData []byte, cert *cmapi.Certificate) []byte {
	csrPEM, err := generateCSRImpl(cert, pkData)
	if err != nil {
		t.Fatal(err)
	}
	return csrPEM
}

// mustCreatePEMPrivateKey returns a PEM encoded 2048 bit RSA private key.
func mustCreatePEMPrivateKey(t *testing.T) []byte {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pkData, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
	if err != nil {
		t.Fatal(err)
	}
	return pkData
}

// mustCreateCertWithNotBeforeAfter returns a self-signed X509 cert for Certificate
// with the provided NotBefore, NotAfter values
func mustCreateCertWithNotBeforeAfter(t *testing.T, pkData []byte, spec *cmapi.Certificate, notBefore, notAfter time.Time) []byte {
	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		t.Fatal(err)
	}

	template, err := pki.GenerateTemplate(spec)
	if err != nil {
		t.Fatal(err)
	}

	template.NotBefore = notBefore
	template.NotAfter = notAfter

	certData, _, err := pki.SignCertificate(template, template, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}

	return certData
}

// mustCreateCert returns a self-signed X509 certificate
func mustCreateCert(t *testing.T, pkData []byte, spec *cmapi.Certificate) []byte {
	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		t.Fatal(err)
	}

	template, err := pki.GenerateTemplate(spec)
	if err != nil {
		t.Fatal(err)
	}

	certData, _, err := pki.SignCertificate(template, template, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}

	return certData
}

// generateCSRImpl returns a PEM encoded certificate signing request for the certificate
func generateCSRImpl(crt *cmapi.Certificate, pk []byte) ([]byte, error) {
	csr, err := pki.GenerateCSR(crt)
	if err != nil {
		return nil, err
	}

	signer, err := pki.DecodePrivateKeyBytes(pk)
	if err != nil {
		return nil, err
	}

	csrDER, err := pki.EncodeCSR(csr, signer)
	if err != nil {
		return nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDER,
	})

	return csrPEM, nil
}
