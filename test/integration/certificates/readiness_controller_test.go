/*
Copyright 2025 The cert-manager Authors.

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
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/readiness"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
)

// TestReadinessController_ExpiryWithoutEvents checks that a Certificate stops
// reporting Ready=True once it expires, even when nothing else changes.
//
// This is the case reported in issue #7895: renewal is stuck, so the readiness
// controller never sees a watch event and the Certificate looks healthy long
// after it expired.
func TestReadinessController_ExpiryWithoutEvents(t *testing.T) {
	config, stopFn := framework.RunControlPlane(t)
	t.Cleanup(stopFn)

	fakeClock := &fakeclock.FakeClock{}
	fakeClock.SetTime(time.Now())

	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)

	namespace := "testns-readiness-expiry"
	secretName := "example"
	certName := "testcrt"

	now := fakeClock.Now()
	notBefore := now
	notAfter := now.Add(3 * time.Hour)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	if _, err := kubeClient.CoreV1().Namespaces().Create(t.Context(), ns, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: certName, Namespace: namespace},
		Spec: cmapi.CertificateSpec{
			SecretName: secretName,
			CommonName: "example.com",
			IssuerRef:  cmmeta.IssuerReference{Name: "testissuer"}, // doesn't need to exist
		},
	}

	sk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	skBytes := pki.EncodePKCS1PrivateKey(sk)
	x509CertBytes := selfSignCertificateWithNotBeforeAfter(t, skBytes, cert, notBefore, notAfter)

	_, err = kubeClient.CoreV1().Secrets(namespace).Create(t.Context(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: skBytes,
			corev1.TLSCertKey:       x509CertBytes,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	controllerContext := &controllerpkg.Context{
		Scheme:                    scheme,
		Client:                    kubeClient,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmCl,
		SharedInformerFactory:     cmFactory,
		Clock:                     fakeClock,
		ContextOptions:            controllerpkg.ContextOptions{},
		Recorder:                  framework.NewEventRecorder(t, scheme),
		FieldManager:              "cert-manager-certificates-readiness-test",
	}
	ctrl, queue, mustSync, err := readiness.NewController(
		logf.Log,
		controllerContext,
		policies.NewReadinessPolicyChain(fakeClock),
		pki.RenewalTime,
		readiness.BuildReadyConditionFromChain,
	)
	if err != nil {
		t.Fatal(err)
	}
	c := controllerpkg.NewController(
		"readiness_test",
		metrics.New(logf.Log, clock.RealClock{}),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	if _, err := cmCl.CertmanagerV1().Certificates(namespace).Create(t.Context(), cert, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	t.Log("Waiting for the Certificate to become Ready")
	waitForReadyCondition(t, t.Context(), cmCl, namespace, certName, cmmeta.ConditionTrue, readiness.ReadyReason)

	// Nothing else changes here: no Secret update, no CertificateRequest, no
	// edit to the Certificate. Only a re-check the controller scheduled for
	// itself can wake it up.
	t.Log("Advancing the clock past the certificate's expiry")
	fakeClock.SetTime(notAfter.Add(2 * time.Second))

	t.Log("Waiting for the Certificate to report that it has expired")
	waitForReadyCondition(t, t.Context(), cmCl, namespace, certName, cmmeta.ConditionFalse, policies.Expired)
}

// waitForReadyCondition polls until the Ready condition matches status and reason.
func waitForReadyCondition(t *testing.T, ctx context.Context, cmCl cmclient.Interface, namespace, name string, status cmmeta.ConditionStatus, reason string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var last *cmapi.CertificateCondition
	err := wait.PollUntilContextCancel(ctx, 200*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		crt, err := cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		last = apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionReady)
		if last == nil {
			return false, nil
		}
		return last.Status == status && last.Reason == reason, nil
	})
	if err != nil {
		t.Fatalf("expected Ready condition with status %q and reason %q, last seen %+v: %v", status, reason, last, err)
	}
}
