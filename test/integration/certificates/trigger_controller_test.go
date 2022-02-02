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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/trigger"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/integration/framework"
)

// TestTriggerController performs a basic test to ensure that the trigger
// controller works when instantiated.
// This is not an exhaustive set of test cases. It only ensures that an
// issuance is triggered when a new Certificate resource is created and
// no Secret exists.
func TestTriggerController(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	fakeClock := &fakeclock.FakeClock{}
	// Build, instantiate and run the trigger controller.
	kubeClient, factory, cmCl, cmFactory := framework.NewClients(t, config)

	namespace := "testns"

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	shouldReissue := policies.NewTriggerPolicyChain(fakeClock).Evaluate
	ctrl, queue, mustSync := trigger.NewController(logf.Log, cmCl, factory, cmFactory, framework.NewEventRecorder(t), fakeClock, shouldReissue)
	c := controllerpkg.NewController(
		ctx,
		"trigger_test",
		metrics.New(logf.Log, clock.RealClock{}),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	// Create a Certificate resource and wait for it to have the 'Issuing' condition.
	cert, err := cmCl.CertmanagerV1().Certificates(namespace).Create(ctx, &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "testcrt", Namespace: "testns"},
		Spec: cmapi.CertificateSpec{
			SecretName: "example",
			CommonName: "example.com",
			IssuerRef:  cmmeta.ObjectReference{Name: "testissuer"}, // doesn't need to exist
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = wait.PollImmediateUntil(time.Millisecond*100, func() (done bool, err error) {
		c, err := cmCl.CertmanagerV1().Certificates(cert.Namespace).Get(ctx, cert.Name, metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Certificate resource, retrying: %v", err)
			return false, nil
		}
		if !apiutil.CertificateHasCondition(c, cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionIssuing,
			Status: cmmeta.ConditionTrue,
		}) {
			t.Logf("Certificate does not have expected condition, got=%#v", apiutil.GetCertificateCondition(c, cmapi.CertificateConditionIssuing))
			return false, nil
		}
		return true, nil
	}, ctx.Done())
	if err != nil {
		t.Fatal(err)
	}
}

func TestTriggerController_RenewNearExpiry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	fakeClock := &fakeclock.FakeClock{}
	// Only use the 'current certificate nearing expiry' policy chain during the
	// test as we want to test the very specific cases of triggering/not
	// triggering depending on whether a renewal is required.
	shoudReissue := policies.Chain{policies.CurrentCertificateNearingExpiry(fakeClock)}.Evaluate
	// Build, instantiate and run the trigger controller.
	kubeClient, factory, cmCl, cmFactory := framework.NewClients(t, config)

	namespace := "testns"
	secretName := "example"
	certName := "testcrt"

	now := fakeClock.Now()
	notBefore := metav1.NewTime(now)
	notAfter := metav1.NewTime(now.Add(time.Hour * 3))
	renewBefore := &metav1.Duration{Duration: time.Hour}

	// Create namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create Certificate template
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: certName, Namespace: namespace},
		Spec: cmapi.CertificateSpec{
			SecretName:  secretName,
			CommonName:  "example.com",
			RenewBefore: renewBefore,
			IssuerRef:   cmmeta.ObjectReference{Name: "testissuer"}, // doesn't need to exist
		},
	}

	// Create a private key for X.509 cert
	sk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	skBytes := pki.EncodePKCS1PrivateKey(sk)
	// Create an X.509 cert
	x509CertBytes := selfSignCertificateWithNotBeforeAfter(t, skBytes, cert, notBefore.Time, notAfter.Time)
	// Create a Secret with the X.509 cert
	_, err = kubeClient.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey: x509CertBytes,
		},
	}, metav1.CreateOptions{})

	if err != nil {
		t.Fatal(err)
	}

	// Start the trigger controller
	ctrl, queue, mustSync := trigger.NewController(logf.Log, cmCl, factory, cmFactory, framework.NewEventRecorder(t), fakeClock, shoudReissue)
	c := controllerpkg.NewController(
		logf.NewContext(ctx, logf.Log, "trigger_controller_RenewNearExpiry"),
		"trigger_test",
		metrics.New(logf.Log, clock.RealClock{}),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	// Create a Certificate
	cert, err = cmCl.CertmanagerV1().Certificates(namespace).Create(ctx, cert, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Test that the Certificate's Issuing condition is not set to True when the
	// X.509 cert is not approaching expiry.
	// Wait for 2s, polling every 200ms to ensure that the controller does not set
	// the condition.
	t.Log("Ensuring Certificate does not have Issuing condition for 2s...")
	ensureCertificateDoesNotHaveIssuingCondition(ctx, t, cmCl, namespace, certName)

	// 2. Test that a Certificate does get the Issuing status condition set to
	// True when the X.509 cert is nearing expiry.
	t.Log("Advancing the clock forward to renewal time")
	// Advance the clock to a millisecond after renewal time.
	// fakeclock implementation uses .After when checking whether to trigger timers.
	// renewalTime = notAfter - renewBefore
	renewalTime := notAfter.Add(renewBefore.Duration * -1)
	fakeClock.SetTime(renewalTime.Add(time.Millisecond * 2))

	// Certificate's status.RenewalTime does not determine renewal, but we need to
	// update some field to trigger a reconcile.
	someRenewalTime := metav1.NewTime(now)
	cert.Status.RenewalTime = &someRenewalTime
	cert, err = cmCl.CertmanagerV1().Certificates(namespace).UpdateStatus(ctx, cert, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	err = wait.PollImmediateUntil(time.Millisecond*200, func() (done bool, err error) {
		c, err := cmCl.CertmanagerV1().Certificates(cert.Namespace).Get(ctx, cert.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if apiutil.CertificateHasCondition(c, cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionIssuing,
			Status: cmmeta.ConditionTrue,
		}) {
			return true, nil
		}
		return false, nil
	}, ctx.Done())
	if err != nil {
		t.Error("Failed waiting for Certificate to have Issuing condition")
	}
}

func ensureCertificateDoesNotHaveIssuingCondition(ctx context.Context, t *testing.T, cmCl cmclient.Interface, namespace, name string) {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()

	err := wait.PollImmediateUntil(time.Millisecond*200, func() (done bool, err error) {
		c, err := cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if apiutil.CertificateHasCondition(c, cmapi.CertificateCondition{
			Type:   cmapi.CertificateConditionIssuing,
			Status: cmmeta.ConditionTrue,
		}) {
			t.Logf("Certificate has unexpected 'Issuing' condition, got=%#v", apiutil.GetCertificateCondition(c, cmapi.CertificateConditionIssuing))
			return true, nil
		}
		return false, nil
	}, timeoutCtx.Done())
	switch {
	case err == nil:
		t.Fatal("expected Certificate to not have the Issuing condition")
	case err == wait.ErrWaitTimeout:
		if ctx.Err() != nil {
			t.Error(ctx.Err())
		}

		// this is the expected 'happy case'
	default:
		t.Fatal(err)
	}
}

func selfSignCertificateWithNotBeforeAfter(t *testing.T, pkData []byte, spec *cmapi.Certificate, notBefore, notAfter time.Time) []byte {
	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		t.Fatal(err)
	}

	template, err := pki.GenerateTemplate(spec)
	if err != nil {
		t.Fatal(err)
	}

	// override the NotAfter, NotBefore fields that by default are set based on time.Now
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	certData, _, err := pki.SignCertificate(template, template, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	return certData
}
