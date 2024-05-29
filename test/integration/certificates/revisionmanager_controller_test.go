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
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/revisionmanager"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// TestRevisionManagerController will ensure that the revision manager
// controller will delete old CertificateRequests occording to the
// spec.revisionHistoryLimit value
func TestRevisionManagerController(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build, instantiate and run the revision manager controller.
	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)

	controllerContext := controllerpkg.Context{
		Scheme:                scheme,
		CMClient:              cmCl,
		SharedInformerFactory: cmFactory,
	}

	ctrl, queue, mustSync := revisionmanager.NewController(logf.Log, &controllerContext)

	c := controllerpkg.NewController(
		"revisionmanager_controller_test",
		metrics.New(logf.Log, clock.RealClock{}),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	var (
		crtName    = "testcrt"
		namespace  = "testns"
		secretName = "test-crt-tls"
	)

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create Certificate
	crt := gen.Certificate(crtName,
		gen.SetCertificateNamespace(namespace),
		gen.SetCertificateCommonName("my-common-name"),
		gen.SetCertificateSecretName(secretName),
		gen.SetCertificateRevisionHistoryLimit(3),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "testissuer", Group: "foo.io", Kind: "Issuer"}),
	)

	crt, err = cmCl.CertmanagerV1().Certificates(namespace).Create(ctx, crt, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Set Certificate to Ready
	apiutil.SetCertificateCondition(crt, crt.Generation,
		cmapi.CertificateConditionReady, cmmeta.ConditionTrue, "Issued", "integration test")
	crt, err = cmCl.CertmanagerV1().Certificates(namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create a new private key
	sk, err := utilpki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

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

	// Create 6 CertificateRequests which are owned by this Certificate
	for i := 0; i < 6; i++ {
		_, err = cmCl.CertmanagerV1().CertificateRequests(namespace).Create(ctx, &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: crtName + "-",
				Namespace:    namespace,
				Annotations: map[string]string{
					cmapi.CertificateRequestRevisionAnnotationKey: strconv.Itoa(i),
				},
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate")),
				},
			},
			Spec: cmapi.CertificateRequestSpec{
				Request:   csrPEM,
				IssuerRef: cmmeta.ObjectReference{Name: "testissuer", Group: "foo.io", Kind: "Issuer"},
			},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}

	var crs []cmapi.CertificateRequest

	// Wait for 3 CertificateRequests to be deleted, and that they have the correct revisions
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
		requests, err := cmCl.CertmanagerV1().CertificateRequests(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		if len(requests.Items) != 3 {
			t.Logf("waiting for 3 requests to be deleted, got=%d", len(requests.Items))
			return false, nil
		}

		crs = requests.Items

		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Expect that the remaining requests have the largest revisions (3, 4, 5)
	for _, revision := range []string{"3", "4", "5"} {
		var found bool
		for _, cr := range crs {
			if cr.Annotations[cmapi.CertificateRequestRevisionAnnotationKey] == revision {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("failed to find a CertificateRequest with a revision=%s", revision)
		}
	}
}
