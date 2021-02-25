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
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/integration/framework"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// TestIssuingController performs a basic test to ensure that the issuing
// controller works when instantiated.
// This is not an exhaustive set of test cases. It only ensures that the signed
// certificate, ca, and private key is stored into the target Secret to
// complete Issuing the Certificate.
func TestIssuingController(t *testing.T) {
	config, stopFn := framework.RunControlPlane(t)
	defer stopFn()

	// Build, instantiate and run the issuing controller.
	kubeClient, factory, cmCl, cmFactory := framework.NewClients(t, config)
	controllerOptions := controllerpkg.CertificateOptions{
		EnableOwnerRef: true,
	}

	ctrl, queue, mustSync := issuing.NewController(logf.Log, kubeClient, cmCl, factory, cmFactory, framework.NewEventRecorder(t), clock.RealClock{}, controllerOptions)
	c := controllerpkg.NewController(
		context.Background(),
		"issuing_test",
		metrics.New(logf.Log),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*20)
	defer cancel()

	var (
		crtName                  = "testcrt"
		revision                 = 1
		namespace                = "testns"
		nextPrivateKeySecretName = "next-private-key-test-crt"
		secretName               = "test-crt-tls"
	)

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create a new private key
	sk, err := utilpki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	// Encode the private key as PKCS#1, the default format
	skBytes := utilpki.EncodePKCS1PrivateKey(sk)

	// Store new private key in secret
	_, err = kubeClient.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nextPrivateKeySecretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: skBytes,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create Certificate
	crt := gen.Certificate(crtName,
		gen.SetCertificateNamespace(namespace),
		gen.SetCertificateCommonName("my-common-name"),
		gen.SetCertificateDNSNames("example.com", "foo.example.com"),
		gen.SetCertificateIPs("1.2.3.4", "5.6.7.8"),
		gen.SetCertificateURIs("spiffe://hello.world"),
		gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
		gen.SetCertificateKeySize(2048),
		gen.SetCertificateSecretName(secretName),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "testissuer", Group: "foo.io", Kind: "Issuer"}),
	)

	crt, err = cmCl.CertmanagerV1().Certificates(namespace).Create(ctx, crt, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create x509 CSR from Certificate
	csr, err := utilpki.GenerateCSR(crt)
	if err != nil {
		t.Fatal(err)
	}

	// Encode CSR
	csrDER, err := utilpki.EncodeCSR(csr, sk)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDER,
	})

	// Sign Certificate
	certTemplate, err := utilpki.GenerateTemplate(crt)
	if err != nil {
		t.Fatal(err)
	}

	// Sign and encode the certificate
	certPem, _, err := utilpki.SignCertificate(certTemplate, certTemplate, sk.Public(), sk)
	if err != nil {
		t.Fatal(err)
	}

	// Create CertificateRequest
	req := gen.CertificateRequest(crtName,
		gen.SetCertificateRequestNamespace(namespace),
		gen.SetCertificateRequestCSR(csrPEM),
		gen.SetCertificateRequestIssuer(crt.Spec.IssuerRef),
		gen.SetCertificateRequestAnnotations(map[string]string{
			cmapi.CertificateRequestRevisionAnnotationKey: fmt.Sprintf("%d", revision+1),
		}),
		gen.AddCertificateRequestOwnerReferences(*metav1.NewControllerRef(
			crt,
			cmapi.SchemeGroupVersion.WithKind("Certificate"),
		)),
	)
	req, err = cmCl.CertmanagerV1().CertificateRequests(namespace).Create(ctx, req, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Set CertificateRequest as ready
	req.Status.CA = certPem
	req.Status.Certificate = certPem
	apiutil.SetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "")
	req, err = cmCl.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(ctx, req, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Add Issuing condition to Certificate
	apiutil.SetCertificateCondition(crt, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "", "")
	crt.Status.NextPrivateKeySecretName = &nextPrivateKeySecretName
	crt.Status.Revision = &revision
	crt, err = cmCl.CertmanagerV1().Certificates(namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the Certificate to have the 'Issuing' condition removed, and for
	// the signed certificate, ca, and private key stored in the Secret.
	err = wait.Poll(time.Millisecond*100, time.Second*5, func() (done bool, err error) {
		crt, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, crtName, metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Certificate resource, retrying: %v", err)
			return false, nil
		}

		if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing); cond != nil {
			t.Logf("Certificate does not have expected condition, got=%#v", cond)
			return false, nil
		}

		// If the condition is set, but the rest of the values are not there,
		// error. This is to assert that all Secret data and metadata is pushed in
		// a single resource update.

		if crt.Status.Revision == nil ||
			*crt.Status.Revision != 2 {
			return false, fmt.Errorf("Certificate does not have a revision of 2: %v", crt.Status.Revision)
		}

		secret, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, crt.Spec.SecretName, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("Failed to fetch Secret %s/%s: %s", namespace, crt.Spec.SecretName, err)
		}

		if !bytes.Equal(secret.Data[corev1.TLSPrivateKeyKey], skBytes) ||
			!bytes.Equal(secret.Data[corev1.TLSCertKey], certPem) ||
			!bytes.Equal(secret.Data[cmmeta.TLSCAKey], certPem) {
			return false, fmt.Errorf("Contents of secret did not match expected: %+v", secret.Data)
		}

		for expKey, expV := range map[string]string{
			cmapi.AltNamesAnnotationKey:    "example.com,foo.example.com",
			cmapi.IPSANAnnotationKey:       "1.2.3.4,5.6.7.8",
			cmapi.URISANAnnotationKey:      "spiffe://hello.world",
			cmapi.CommonNameAnnotationKey:  "my-common-name",
			cmapi.IssuerNameAnnotationKey:  "testissuer",
			cmapi.IssuerKindAnnotationKey:  "Issuer",
			cmapi.IssuerGroupAnnotationKey: "foo.io",
			cmapi.CertificateNameKey:       "testcrt",
		} {
			if v, ok := secret.Annotations[expKey]; !ok || expV != v {
				return false, fmt.Errorf("expected Secret to have the annotation %s:%s, got %s:%s",
					expKey, expV, expKey, v)
			}
		}

		return true, nil
	})

	if err != nil {
		t.Fatalf("Failed to wait for final state: %+v", crt)
	}
}

func TestIssuingController_PKCS8_PrivateKey(t *testing.T) {
	config, stopFn := framework.RunControlPlane(t)
	defer stopFn()

	// Build, instantiate and run the issuing controller.
	kubeClient, factory, cmCl, cmFactory := framework.NewClients(t, config)
	controllerOptions := controllerpkg.CertificateOptions{
		EnableOwnerRef: true,
	}

	ctrl, queue, mustSync := issuing.NewController(logf.Log, kubeClient, cmCl, factory, cmFactory, framework.NewEventRecorder(t), clock.RealClock{}, controllerOptions)
	c := controllerpkg.NewController(
		context.Background(),
		"issuing_test",
		metrics.New(logf.Log),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*20)
	defer cancel()

	var (
		crtName                  = "testcrt"
		revision                 = 1
		namespace                = "testns"
		nextPrivateKeySecretName = "next-private-key-test-crt"
		secretName               = "test-crt-tls"
	)

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create a new private key
	sk, err := utilpki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	// Encode the private key as PKCS#1, the default format
	skBytesPKCS1 := utilpki.EncodePKCS1PrivateKey(sk)
	skBytesPKCS8, err := utilpki.EncodePKCS8PrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}

	// Store new private key in secret
	_, err = kubeClient.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nextPrivateKeySecretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			// store PKCS#1 bytes so we can ensure they are correctly converted to
			// PKCS#8 later on
			corev1.TLSPrivateKeyKey: skBytesPKCS1,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create Certificate
	crt := gen.Certificate(crtName,
		gen.SetCertificateNamespace(namespace),
		gen.SetCertificateCommonName("my-common-name"),
		gen.SetCertificateDNSNames("example.com", "foo.example.com"),
		gen.SetCertificateIPs("1.2.3.4", "5.6.7.8"),
		gen.SetCertificateURIs("spiffe://hello.world"),
		gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
		gen.SetCertificateKeyEncoding(cmapi.PKCS8),
		gen.SetCertificateKeySize(2048),
		gen.SetCertificateSecretName(secretName),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "testissuer", Group: "foo.io", Kind: "Issuer"}),
	)

	crt, err = cmCl.CertmanagerV1().Certificates(namespace).Create(ctx, crt, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create x509 CSR from Certificate
	csr, err := utilpki.GenerateCSR(crt)
	if err != nil {
		t.Fatal(err)
	}

	// Encode CSR
	csrDER, err := utilpki.EncodeCSR(csr, sk)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDER,
	})

	// Sign Certificate
	certTemplate, err := utilpki.GenerateTemplate(crt)
	if err != nil {
		t.Fatal(err)
	}

	// Sign and encode the certificate
	certPem, _, err := utilpki.SignCertificate(certTemplate, certTemplate, sk.Public(), sk)
	if err != nil {
		t.Fatal(err)
	}

	// Create CertificateRequest
	req := gen.CertificateRequest(crtName,
		gen.SetCertificateRequestNamespace(namespace),
		gen.SetCertificateRequestCSR(csrPEM),
		gen.SetCertificateRequestIssuer(crt.Spec.IssuerRef),
		gen.SetCertificateRequestAnnotations(map[string]string{
			cmapi.CertificateRequestRevisionAnnotationKey: fmt.Sprintf("%d", revision+1),
		}),
		gen.AddCertificateRequestOwnerReferences(*metav1.NewControllerRef(
			crt,
			cmapi.SchemeGroupVersion.WithKind("Certificate"),
		)),
	)
	req, err = cmCl.CertmanagerV1().CertificateRequests(namespace).Create(ctx, req, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Set CertificateRequest as ready
	req.Status.CA = certPem
	req.Status.Certificate = certPem
	apiutil.SetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "")
	req, err = cmCl.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(ctx, req, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Add Issuing condition to Certificate
	apiutil.SetCertificateCondition(crt, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "", "")
	crt.Status.NextPrivateKeySecretName = &nextPrivateKeySecretName
	crt.Status.Revision = &revision
	crt, err = cmCl.CertmanagerV1().Certificates(namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the Certificate to have the 'Issuing' condition removed, and for
	// the signed certificate, ca, and private key stored in the Secret.
	err = wait.Poll(time.Millisecond*100, time.Second*5, func() (done bool, err error) {
		crt, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, crtName, metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Certificate resource, retrying: %v", err)
			return false, nil
		}

		if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing); cond != nil {
			t.Logf("Certificate does not have expected condition, got=%#v", cond)
			return false, nil
		}

		// If the condition is set, but the rest of the values are not there,
		// error. This is to assert that all Secret data and metadata is pushed in
		// a single resource update.

		if crt.Status.Revision == nil ||
			*crt.Status.Revision != 2 {
			return false, fmt.Errorf("Certificate does not have a revision of 2: %v", crt.Status.Revision)
		}

		secret, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, crt.Spec.SecretName, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("Failed to fetch Secret %s/%s: %s", namespace, crt.Spec.SecretName, err)
		}

		if !bytes.Equal(secret.Data[corev1.TLSPrivateKeyKey], skBytesPKCS8) ||
			!bytes.Equal(secret.Data[corev1.TLSCertKey], certPem) ||
			!bytes.Equal(secret.Data[cmmeta.TLSCAKey], certPem) {
			return false, fmt.Errorf("Contents of secret did not match expected: %+v", secret.Data)
		}

		for expKey, expV := range map[string]string{
			cmapi.AltNamesAnnotationKey:    "example.com,foo.example.com",
			cmapi.IPSANAnnotationKey:       "1.2.3.4,5.6.7.8",
			cmapi.URISANAnnotationKey:      "spiffe://hello.world",
			cmapi.CommonNameAnnotationKey:  "my-common-name",
			cmapi.IssuerNameAnnotationKey:  "testissuer",
			cmapi.IssuerKindAnnotationKey:  "Issuer",
			cmapi.IssuerGroupAnnotationKey: "foo.io",
			cmapi.CertificateNameKey:       "testcrt",
		} {
			if v, ok := secret.Annotations[expKey]; !ok || expV != v {
				return false, fmt.Errorf("expected Secret to have the annotation %s:%s, got %s:%s",
					expKey, expV, expKey, v)
			}
		}

		return true, nil
	})
	if err != nil {
		t.Fatalf("Failed to wait for final state: %+v", crt)
	}
}
