/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"fmt"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/renew"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/expcertificates/issuing"
	"github.com/jetstack/cert-manager/pkg/controller/expcertificates/readiness"
	"github.com/jetstack/cert-manager/pkg/controller/expcertificates/trigger/policies"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/integration/framework"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

// TestCtlRenew tests the renewal logic of the ctl CLI command against the
// cert-manager Issuing controller.
func TestCtlRenew(t *testing.T) {
	config, stopFn := framework.RunControlPlane(t)
	defer stopFn()

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*20)
	defer cancel()

	// Build, instantiate and run the issuing controller.
	kubeClient, factory, cmCl, cmFactory := framework.NewClients(t, config)
	controllerOptions := controllerpkg.CertificateOptions{
		EnableOwnerRef: true,
	}
	recorder := framework.NewEventRecorder(t)

	var (
		crtName                  = "testcrt"
		revision                 = 1
		namespace                = "testns"
		nextPrivateKeySecretName = "next-private-key-test-crt"
		secretName               = "test-crt-tls"
	)

	// Create a new private key
	sk, err := utilpki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

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
		gen.SetCertificateDNSNames("example.com"),
		gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
		gen.SetCertificateKeySize(2048),
		gen.SetCertificateSecretName(secretName),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "testissuer"}),
	)

	crt, err = cmCl.CertmanagerV1alpha2().Certificates(namespace).Create(ctx, crt, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Init and start controllers
	ctrlIssuing, queueIssuing, mustSyncIssuing := issuing.NewController(logf.Log, kubeClient, cmCl, factory, cmFactory, recorder, clock.RealClock{}, controllerOptions)
	ctrlReadiness, queueReadiness, mustSyncReadiness := readiness.NewController(logf.Log, cmCl, factory, cmFactory, policies.TriggerPolicyChain)

	for _, ctrl := range []struct {
		syncFunc func(ctx context.Context, key string) error
		mustSync []cache.InformerSynced
		queue    workqueue.RateLimitingInterface
	}{
		{ctrlIssuing.ProcessItem, mustSyncIssuing, queueIssuing},
		{ctrlReadiness.ProcessItem, mustSyncReadiness, queueReadiness},
	} {
		c := controllerpkg.NewController(
			context.Background(),
			ctrl.syncFunc,
			ctrl.mustSync,
			nil,
			ctrl.queue,
		)

		stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
		defer stopController()
	}

	// Add Issuing condition to Certificate
	apiutil.SetCertificateCondition(crt, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "", "")
	crt.Status.NextPrivateKeySecretName = &nextPrivateKeySecretName
	crt.Status.Revision = &revision
	crt, err = cmCl.CertmanagerV1alpha2().Certificates(namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
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
	req, err = cmCl.CertmanagerV1alpha2().CertificateRequests(namespace).Create(ctx, req, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Set CertificateRequest as ready
	req.Status.CA = certPem
	req.Status.Certificate = certPem
	apiutil.SetCertificateRequestCondition(req, cmapi.CertificateRequestConditionReady, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "")
	req, err = cmCl.CertmanagerV1alpha2().CertificateRequests(namespace).UpdateStatus(ctx, req, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Run ctl renew command and wait for ready
	streams, _, _, _ := genericclioptions.NewTestIOStreams()
	streams.Out = os.Stdout

	cmd := &renew.Options{
		Namespace:  "testns",
		CMClient:   cmCl,
		RestConfig: config,
		Wait:       true,
		Timeout:    time.Second * 10,
		IOStreams:  streams,
	}

	if err := cmd.Run([]string{"testcrt"}); err != nil {
		t.Fatal(err)
	}
}
