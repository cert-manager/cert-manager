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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	applycorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	applymetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// TestIssuingController performs a basic test to ensure that the issuing
// controller works when instantiated.
// This is not an exhaustive set of test cases. It only ensures that the signed
// certificate, ca, and private key is stored into the target Secret to
// complete Issuing the Certificate.
func TestIssuingController(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build, instantiate and run the issuing controller.
	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)
	controllerOptions := controllerpkg.CertificateOptions{
		EnableOwnerRef: true,
	}
	controllerContext := controllerpkg.Context{
		Client:                    kubeClient,
		Scheme:                    scheme,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmCl,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Clock:              clock.RealClock{},
			CertificateOptions: controllerOptions,
		},
		Recorder:     framework.NewEventRecorder(t, scheme),
		FieldManager: "cert-manager-certificates-issuing-test",
	}

	ctrl, queue, mustSync, err := issuing.NewController(logf.Log, &controllerContext)
	require.NoError(t, err)
	c := controllerpkg.NewController(
		"issuing_test",
		metrics.New(logf.Log, clock.RealClock{}),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	var (
		crtName                  = "testcrt"
		revision                 = 1
		namespace                = "testns"
		nextPrivateKeySecretName = "next-private-key-test-crt"
		secretName               = "test-crt-tls"
	)

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	if _, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
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

	csrPEM, err := gen.CSRWithSignerForCertificate(crt, sk)
	if err != nil {
		t.Fatal(err)
	}

	// Sign Certificate
	certTemplate, err := utilpki.CertificateTemplateFromCertificate(crt)
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
	_, err = cmCl.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(ctx, req, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Add Issuing condition to Certificate
	apiutil.SetCertificateCondition(crt, crt.Generation, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "", "")
	crt.Status.NextPrivateKeySecretName = &nextPrivateKeySecretName
	crt.Status.Revision = &revision
	crt, err = cmCl.CertmanagerV1().Certificates(namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the Certificate to have the 'Issuing' condition removed, and
	// for the signed certificate, ca, and private key stored in the Secret.
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build, instantiate and run the issuing controller.
	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)
	controllerOptions := controllerpkg.CertificateOptions{
		EnableOwnerRef: true,
	}
	controllerContext := controllerpkg.Context{
		Client:                    kubeClient,
		Scheme:                    scheme,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmCl,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Clock:              clock.RealClock{},
			CertificateOptions: controllerOptions,
		},
		Recorder:     framework.NewEventRecorder(t, scheme),
		FieldManager: "cert-manager-certificates-issuing-test",
	}

	ctrl, queue, mustSync, err := issuing.NewController(logf.Log, &controllerContext)
	require.NoError(t, err)
	c := controllerpkg.NewController(
		"issuing_test",
		metrics.New(logf.Log, clock.RealClock{}),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	var (
		crtName                  = "testcrt"
		revision                 = 1
		namespace                = "testns"
		nextPrivateKeySecretName = "next-private-key-test-crt"
		secretName               = "test-crt-tls"
	)

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	if _, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
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

	csrPEM, err := gen.CSRWithSignerForCertificate(crt, sk)
	if err != nil {
		t.Fatal(err)
	}

	// Sign Certificate
	certTemplate, err := utilpki.CertificateTemplateFromCertificate(crt)
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
	_, err = cmCl.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(ctx, req, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Add Issuing condition to Certificate
	apiutil.SetCertificateCondition(crt, crt.Generation, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "", "")
	crt.Status.NextPrivateKeySecretName = &nextPrivateKeySecretName
	crt.Status.Revision = &revision
	crt, err = cmCl.CertmanagerV1().Certificates(namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the Certificate to have the 'Issuing' condition removed, and for
	// the signed certificate, ca, and private key stored in the Secret.
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
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

// Test_IssuingController_SecretTemplate performs a basic check to ensure that
// values in a Certificate's SecretTemplate will be copied to the target
// Secret - when they are both added and deleted.
func Test_IssuingController_SecretTemplate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build, instantiate and run the issuing controller.
	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)
	controllerOptions := controllerpkg.CertificateOptions{
		EnableOwnerRef: true,
	}
	controllerContext := controllerpkg.Context{
		Client:                    kubeClient,
		Scheme:                    scheme,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmCl,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Clock:              clock.RealClock{},
			CertificateOptions: controllerOptions,
		},
		Recorder:     framework.NewEventRecorder(t, scheme),
		FieldManager: "cert-manager-certificates-issuing-test",
	}

	ctrl, queue, mustSync, err := issuing.NewController(logf.Log, &controllerContext)
	require.NoError(t, err)
	c := controllerpkg.NewController(
		"issuing_test",
		metrics.New(logf.Log, clock.RealClock{}),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	var (
		crtName                  = "testcrt"
		revision                 = 1
		namespace                = "testns"
		nextPrivateKeySecretName = "next-private-key-test-crt"
		secretName               = "test-crt-tls"
	)

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	if _, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
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

	csrPEM, err := gen.CSRWithSignerForCertificate(crt, sk)
	if err != nil {
		t.Fatal(err)
	}

	// Sign Certificate
	certTemplate, err := utilpki.CertificateTemplateFromCertificate(crt)
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
	_, err = cmCl.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(ctx, req, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Add Issuing condition to Certificate
	apiutil.SetCertificateCondition(crt, crt.Generation, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "", "")
	crt.Status.NextPrivateKeySecretName = &nextPrivateKeySecretName
	crt.Status.Revision = &revision
	crt, err = cmCl.CertmanagerV1().Certificates(namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the Certificate to have the 'Issuing' condition removed, and for
	// the signed certificate, ca, and private key stored in the Secret.
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
		crt, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, crtName, metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Certificate resource, retrying: %v", err)
			return false, nil
		}

		if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing); cond != nil {
			t.Logf("Certificate does not have expected condition, got=%#v", cond)
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add labels and annotations to the SecretTemplate.
	annotations := map[string]string{"annotation-1": "abc", "annotation-2": "123"}
	labels := map[string]string{"labels-1": "abc", "labels-2": "123"}
	crt = gen.CertificateFrom(crt, gen.SetCertificateSecretTemplate(annotations, labels))
	crt, err = cmCl.CertmanagerV1().Certificates(namespace).Update(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the Annotations and Labels to be observed on the Secret.
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
		secret, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Secret resource, retrying: %s", err)
			return false, nil
		}
		for k, v := range annotations {
			if gotV, ok := secret.Annotations[k]; !ok || v != gotV {
				return false, nil
			}
		}
		for k, v := range labels {
			if gotV, ok := secret.Labels[k]; !ok || v != gotV {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Remove labels and annotations from the SecretTemplate.
	crt.Spec.SecretTemplate = nil
	crt, err = cmCl.CertmanagerV1().Certificates(namespace).Update(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the Annotations and Labels to be removed from the Secret.
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
		secret, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Secret resource, retrying: %s", err)
			return false, nil
		}
		for k := range annotations {
			if _, ok := secret.Annotations[k]; ok {
				t.Logf("annotations: %s", secret.Annotations)
				return false, nil
			}
		}
		for k := range labels {
			if _, ok := secret.Labels[k]; ok {
				t.Logf("labels: %s", secret.Labels)
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Test_IssuingController_AdditionalOutputFormats performs a basic check to
// ensure that values in a Certificate's AdditionalOutputFormats will be copied
// to the target Secret - when they are both added and deleted.
func Test_IssuingController_AdditionalOutputFormats(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build, instantiate and run the issuing controller.
	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)
	controllerOptions := controllerpkg.CertificateOptions{
		EnableOwnerRef: true,
	}

	controllerContext := controllerpkg.Context{
		Client:                    kubeClient,
		Scheme:                    scheme,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmCl,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Clock:              clock.RealClock{},
			CertificateOptions: controllerOptions,
		},
		Recorder:     framework.NewEventRecorder(t, scheme),
		FieldManager: "cert-manager-certificates-issuing-test",
	}

	ctrl, queue, mustSync, err := issuing.NewController(logf.Log, &controllerContext)
	require.NoError(t, err)
	c := controllerpkg.NewController(
		"issuing_test",
		metrics.New(logf.Log, clock.RealClock{}),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	var (
		crtName                  = "testcrt"
		revision                 = 1
		namespace                = "testns"
		nextPrivateKeySecretName = "next-private-key-test-crt"
		secretName               = "test-crt-tls"
	)

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	if _, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	// Create a new private key
	pk, err := utilpki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	// Encode the private key as PKCS#1, the default format
	pkBytes := utilpki.EncodePKCS1PrivateKey(pk)

	// Store new private key in secret
	_, err = kubeClient.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nextPrivateKeySecretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: pkBytes,
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

	csrPEM, err := gen.CSRWithSignerForCertificate(crt, pk)
	if err != nil {
		t.Fatal(err)
	}

	// Sign Certificate
	certTemplate, err := utilpki.CertificateTemplateFromCertificate(crt)
	if err != nil {
		t.Fatal(err)
	}

	// Sign and encode the certificate
	certPEM, _, err := utilpki.SignCertificate(certTemplate, certTemplate, pk.Public(), pk)
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
	req.Status.CA = certPEM
	req.Status.Certificate = certPEM
	apiutil.SetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "")
	_, err = cmCl.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(ctx, req, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Add Issuing condition to Certificate
	apiutil.SetCertificateCondition(crt, crt.Generation, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "", "")
	crt.Status.NextPrivateKeySecretName = &nextPrivateKeySecretName
	crt.Status.Revision = &revision
	crt, err = cmCl.CertmanagerV1().Certificates(namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the Certificate to have the 'Issuing' condition removed, and for
	// the signed certificate, ca, and private key stored in the Secret.
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
		crt, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, crtName, metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Certificate resource, retrying: %v", err)
			return false, nil
		}

		if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing); cond != nil {
			t.Logf("Certificate does not have expected condition, got=%#v", cond)
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add additional output formats
	crt = gen.CertificateFrom(crt, gen.SetCertificateAdditionalOutputFormats(
		cmapi.CertificateAdditionalOutputFormat{Type: "CombinedPEM"},
		cmapi.CertificateAdditionalOutputFormat{Type: "DER"},
	))
	crt, err = cmCl.CertmanagerV1().Certificates(namespace).Update(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(pkBytes)
	pkDER := block.Bytes
	combinedPEM := append(append(pkBytes, '\n'), certPEM...)

	// Wait for the additional output format values to be observed on the Secret.
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
		secret, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Secret resource, retrying: %s", err)
			return false, nil
		}
		return reflect.DeepEqual(map[string][]byte{
			"ca.crt": certPEM, "tls.crt": certPEM, "tls.key": pkBytes,
			"key.der": pkDER, "tls-combined.pem": combinedPEM,
		}, secret.Data), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Remove AdditionalOutputFormats
	crt.Spec.AdditionalOutputFormats = nil
	crt, err = cmCl.CertmanagerV1().Certificates(namespace).Update(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the additional output formats to be removed from the Secret.
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
		secret, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Secret resource, retrying: %s", err)
			return false, nil
		}
		return reflect.DeepEqual(map[string][]byte{
			"ca.crt": certPEM, "tls.crt": certPEM, "tls.key": pkBytes,
		}, secret.Data), nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Test_IssuingController_SecretOwnerReference performs a basic check to ensure
// that a Secret is updated with an owner ref if the gate becomes enabled, then
// is removed again when disabled.
// Also ensures that changes to the Secret which modify the owner reference,
// are reverted or corrected if needed by the issuing controller.
func Test_IssuingController_OwnerReference(t *testing.T) {
	const (
		fieldManager = "cert-manager-issuing-test"
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	kubeClient, factory, cmClient, cmFactory, scheme := framework.NewClients(t, config)
	controllerOptions := controllerpkg.CertificateOptions{
		EnableOwnerRef: false,
	}
	controllerContext := controllerpkg.Context{
		Client:                    kubeClient,
		Scheme:                    scheme,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmClient,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Clock:              clock.RealClock{},
			CertificateOptions: controllerOptions,
		},
		Recorder:     framework.NewEventRecorder(t, scheme),
		FieldManager: fieldManager,
	}
	ctrl, queue, mustSync, err := issuing.NewController(logf.Log, &controllerContext)
	require.NoError(t, err)
	c := controllerpkg.NewController(fieldManager, metrics.New(logf.Log, clock.RealClock{}), ctrl.ProcessItem, mustSync, nil, queue)
	stopControllerNoOwnerRef := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer func() {
		if stopControllerNoOwnerRef != nil {
			stopControllerNoOwnerRef()
		}
	}()

	t.Log("creating a Secret and Certificate which does not need issuance")
	ns, err := kubeClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "owner-reference-test"}}, metav1.CreateOptions{})
	require.NoError(t, err)
	crt := gen.Certificate("owner-reference-test",
		gen.SetCertificateNamespace(ns.Name),
		gen.SetCertificateCommonName("my-common-name"),
		gen.SetCertificateDNSNames("example.com", "foo.example.com"),
		gen.SetCertificateIPs("1.2.3.4", "5.6.7.8"),
		gen.SetCertificateURIs("spiffe://hello.world"),
		gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
		gen.SetCertificateKeySize(2048),
		gen.SetCertificateSecretName("cert-manager-issuing-test-secret"),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "testissuer", Group: "foo.io", Kind: "Issuer"}),
	)
	bundle := testcrypto.MustCreateCryptoBundle(t, crt, &clock.RealClock{})
	secret, err := kubeClient.CoreV1().Secrets(ns.Name).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: crt.Spec.SecretName},
		Data: map[string][]byte{
			"ca.crt":  bundle.CertBytes,
			"tls.crt": bundle.CertBytes,
			"tls.key": bundle.PrivateKeyBytes,
		},
	}, metav1.CreateOptions{FieldManager: fieldManager})
	require.NoError(t, err)
	crt, err = cmClient.CertmanagerV1().Certificates(ns.Name).Create(ctx, crt, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Log("ensure Certificate does not gain Issuing condition")
	require.Never(t, func() bool {
		crt, err = cmClient.CertmanagerV1().Certificates(ns.Name).Get(ctx, crt.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue})
	}, time.Second*3, time.Millisecond*10, "expected Certificate to not gain Issuing condition")

	t.Log("added owner reference to Secret for Certificate with field manager should get removed")
	secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
	require.NoError(t, err)
	ref := *metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	applyCnf := applycorev1.Secret(secret.Name, secret.Namespace).
		WithAnnotations(secret.Annotations).WithLabels(secret.Labels).
		WithData(secret.Data).WithType(secret.Type).WithOwnerReferences(&applymetav1.OwnerReferenceApplyConfiguration{
		APIVersion: &ref.APIVersion, Kind: &ref.Kind,
		Name: &ref.Name, UID: &ref.UID,
		Controller: ref.Controller, BlockOwnerDeletion: ref.BlockOwnerDeletion,
	})
	secret, err = kubeClient.CoreV1().Secrets(secret.Namespace).Apply(ctx, applyCnf, metav1.ApplyOptions{FieldManager: fieldManager, Force: true})
	require.NoError(t, err)
	require.Len(t, secret.OwnerReferences, 1)
	require.Eventually(t, func() bool {
		secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return len(secret.OwnerReferences) == 0
	}, time.Second*3, time.Millisecond*10, "expected Secret to have owner reference to Certificate removed: %#+v", secret.OwnerReferences)

	t.Log("added owner reference to Secret for non Certificate UID with field manager should not get removed")
	secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
	require.NoError(t, err)
	fooRef := metav1.OwnerReference{APIVersion: "foo.bar.io/v1", Kind: "Foo", Name: "Bar", UID: types.UID("not-cert"), Controller: ptr.To(false), BlockOwnerDeletion: ptr.To(false)}
	applyCnf.OwnerReferences = []applymetav1.OwnerReferenceApplyConfiguration{{
		APIVersion: &fooRef.APIVersion, Kind: &fooRef.Kind, Name: &fooRef.Name,
		UID: &fooRef.UID, Controller: fooRef.Controller, BlockOwnerDeletion: fooRef.BlockOwnerDeletion,
	}}
	secret, err = kubeClient.CoreV1().Secrets(secret.Namespace).Apply(ctx, applyCnf, metav1.ApplyOptions{FieldManager: fieldManager, Force: true})
	require.NoError(t, err)
	require.Never(t, func() bool {
		secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return !apiequality.Semantic.DeepEqual(secret.OwnerReferences, []metav1.OwnerReference{fooRef})
	}, time.Second*3, time.Millisecond*10, "expected Secret to not have owner reference to Foo removed: %#+v", secret.OwnerReferences)

	t.Log("restarting controller with secret owner reference option enabled")
	stopControllerNoOwnerRef()
	kubeClient, factory, cmClient, cmFactory, _ = framework.NewClients(t, config)
	stopControllerNoOwnerRef = nil
	controllerOptions.EnableOwnerRef = true
	controllerContext = controllerpkg.Context{
		Client:                    kubeClient,
		Scheme:                    scheme,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmClient,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Clock:              clock.RealClock{},
			CertificateOptions: controllerOptions,
		},
		Recorder:     framework.NewEventRecorder(t, scheme),
		FieldManager: fieldManager,
	}
	ctrl, queue, mustSync, err = issuing.NewController(logf.Log, &controllerContext)
	require.NoError(t, err)
	c = controllerpkg.NewController(fieldManager, metrics.New(logf.Log, clock.RealClock{}), ctrl.ProcessItem, mustSync, nil, queue)
	stopControllerOwnerRef := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopControllerOwnerRef()

	t.Log("waiting for owner reference to be set")
	applyCnf.OwnerReferences = nil
	secret, err = kubeClient.CoreV1().Secrets(secret.Namespace).Apply(ctx, applyCnf, metav1.ApplyOptions{FieldManager: fieldManager, Force: true})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return apiequality.Semantic.DeepEqual(secret.OwnerReferences, []metav1.OwnerReference{*metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate"))})
	}, time.Second*10, time.Millisecond*10, "expected Secret to have owner reference to Certificate added: %#+v", secret.OwnerReferences)

	t.Log("deleting the owner reference, should have owner reference added back")
	applyCnf.OwnerReferences = []applymetav1.OwnerReferenceApplyConfiguration{}
	secret, err = kubeClient.CoreV1().Secrets(secret.Namespace).Apply(ctx, applyCnf, metav1.ApplyOptions{FieldManager: fieldManager, Force: true})
	require.NoError(t, err)
	require.Len(t, secret.OwnerReferences, 0)
	require.Eventually(t, func() bool {
		secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return apiequality.Semantic.DeepEqual(secret.OwnerReferences, []metav1.OwnerReference{*metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate"))})
	}, time.Second*3, time.Millisecond*10, "expected Secret to have owner reference to Certificate added: %#+v", secret.OwnerReferences)

	t.Log("changing the options on the owner reference, should have the options reversed")
	secret.OwnerReferences[0].Name = "random-certificate-name"
	secret, err = kubeClient.CoreV1().Secrets(secret.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return apiequality.Semantic.DeepEqual(secret.OwnerReferences, []metav1.OwnerReference{*metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate"))})
	}, time.Second*3, time.Millisecond*10, "expected Secret to have owner reference options to Certificate reverse: %#+v", secret.OwnerReferences)
}
