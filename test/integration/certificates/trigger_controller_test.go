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
	"fmt"
	"testing"
	"time"

	"github.com/segmentio/encoding/json"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"
	fakeclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
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
	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)

	namespace := "testns-trigger"

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	shouldReissue := policies.NewTriggerPolicyChain(fakeClock).Evaluate
	controllerContext := &controllerpkg.Context{
		Scheme:                    scheme,
		Client:                    kubeClient,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmCl,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Clock: fakeClock,
		},
		Recorder:     framework.NewEventRecorder(t, scheme),
		FieldManager: "cert-manager-certificates-trigger-test",
	}
	ctrl, queue, mustSync, err := trigger.NewController(logf.Log, controllerContext, shouldReissue)
	if err != nil {
		t.Fatal(err)
	}
	c := controllerpkg.NewController(
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
		ObjectMeta: metav1.ObjectMeta{Name: "testcrt", Namespace: namespace},
		Spec: cmapi.CertificateSpec{
			SecretName: "example",
			CommonName: "example.com",
			IssuerRef:  cmmeta.ObjectReference{Name: "testissuer"}, // doesn't need to exist
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	ensureCertificateHasIssuingCondition(t, ctx, cmCl, namespace, cert.Name)
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
	shouldReissue := policies.Chain{policies.CurrentCertificateNearingExpiry(fakeClock)}.Evaluate
	// Build, instantiate and run the trigger controller.
	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)

	namespace := "testns-renew-near-expiry"
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

	controllerContext := &controllerpkg.Context{
		Scheme:                    scheme,
		Client:                    kubeClient,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmCl,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Clock: fakeClock,
		},
		Recorder:     framework.NewEventRecorder(t, scheme),
		FieldManager: "cert-manager-certificates-trigger-test",
	}
	// Start the trigger controller
	ctrl, queue, mustSync, err := trigger.NewController(logf.Log, controllerContext, shouldReissue)
	if err != nil {
		t.Fatal(err)
	}
	c := controllerpkg.NewController(
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
	ensureCertificateDoesNotHaveIssuingCondition(t, ctx, cmCl, namespace, certName)

	// 2. Test that a Certificate does get the Issuing status condition set to
	// True when the X.509 cert is nearing expiry.
	t.Log("Advancing the clock forward to renewal time")
	// Advance the clock to a millisecond after renewal time.
	// fakeclock implementation uses .After when checking whether to trigger timers.
	// renewalTime = notAfter - renewBefore
	renewalTime := notAfter.Add(renewBefore.Duration * -1)
	fakeClock.SetTime(renewalTime.Add(time.Millisecond * 2))

	// apply a random condition to cert to ensure the reconciler gets triggered
	applyTestCondition(t, ctx, cert, cmCl)
	ensureCertificateHasIssuingCondition(t, ctx, cmCl, namespace, certName)
}

func TestTriggerController_ExpBackoff(t *testing.T) {
	t.Log("Testing that trigger controller applies exponential backoff when retrying failed issuances...")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	now := time.Now()
	metaNow := metav1.NewTime(now)
	fakeClock := &fakeclock.FakeClock{}
	fakeClock.SetTime(metaNow.Time)
	// Issuing condition will be applied because SecretDoesNotExist policy
	// will evaluate to true. However, this is not what we are testing in
	// this test.
	shouldReissue := policies.NewTriggerPolicyChain(fakeClock).Evaluate
	// Build, instantiate and run the trigger controller.
	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)

	namespace := "testns-expbackoff"
	secretName := "example"
	certName := "testcrt"

	failedIssuanceAttempts := 7
	backoffPeriod := time.Hour * 32

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
			SecretName: secretName,
			CommonName: "example.com",
			IssuerRef:  cmmeta.ObjectReference{Name: "testissuer"}, // doesn't need to exist
		},
	}

	controllerContext := &controllerpkg.Context{
		Scheme:                    scheme,
		Client:                    kubeClient,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmCl,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Clock: fakeClock,
		},
		Recorder:     framework.NewEventRecorder(t, scheme),
		FieldManager: "cert-manager-certificates-trigger-test",
	}

	// Start the trigger controller
	ctrl, queue, mustSync, err := trigger.NewController(logf.Log, controllerContext, shouldReissue)
	if err != nil {
		t.Fatal(err)
	}
	c := controllerpkg.NewController(
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
	_, err = cmCl.CertmanagerV1().Certificates(namespace).Create(ctx, cert, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Test that Issuing condition gets set to True
	t.Log("Ensuring Certificate does get the Issuing condition set to true initially...")
	ensureCertificateHasIssuingCondition(t, ctx, cmCl, namespace, certName)

	// Simulate issuance having failed
	t.Log("Simulate issuance having failed for 7th time in a row")
	cert, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, certName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	apiutil.SetCertificateCondition(cert, 1, cmapi.CertificateConditionIssuing, cmmeta.ConditionFalse, "", "")
	cert.Status.FailedIssuanceAttempts = &failedIssuanceAttempts
	cert.Status.LastFailureTime = &metaNow
	cert, err = cmCl.CertmanagerV1().Certificates(namespace).UpdateStatus(ctx, cert, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Test that issuance is not attempted whilst in backoff period
	// modify some cert field to ensure a reconcile gets triggered
	t.Log("Advance clock to slightly before the end of the backoff period")
	fakeClock.SetTime(now.Add(backoffPeriod - time.Minute))
	// apply a random condition to cert to ensure the reconciler gets triggered
	applyTestCondition(t, ctx, cert, cmCl)

	t.Log("Ensuring Certificate does not have Issuing condition set to true for 2s...")
	ensureCertificateDoesNotHaveIssuingCondition(t, ctx, cmCl, namespace, certName)

	// 3. Test that issuance gets retried once the backoff period is over
	t.Log("Advance clock to just after the backoff period")
	fakeClock.SetTime(now.Add(backoffPeriod + time.Second))
	// apply a random condition to cert to ensure the reconciler gets triggered
	applyTestCondition(t, ctx, cert, cmCl)

	t.Log("Ensuring Certificate does get the Issuing condition set to true after the backoff period")
	ensureCertificateHasIssuingCondition(t, ctx, cmCl, namespace, certName)
}

func ensureCertificateDoesNotHaveIssuingCondition(t *testing.T, ctx context.Context, cmCl cmclient.Interface, namespace, name string) {
	t.Helper()

	startTime := time.Now()
	successful := false
	err := wait.PollUntilContextCancel(ctx, time.Millisecond*200, true, func(ctx context.Context) (bool, error) {
		// Check if certificate has not had condition for 2s
		if time.Since(startTime) > time.Second*2 {
			successful = true
			return true, nil
		}

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
	})
	switch {
	case err == nil && !successful:
		t.Fatal("expected Certificate to not have the Issuing condition")
	case err == nil && successful:
		// this is the expected 'happy case'
	default:
		t.Fatal(err)
	}
}
func ensureCertificateHasIssuingCondition(t *testing.T, ctx context.Context, cmCl cmclient.Interface, namespace, name string) {
	t.Helper()

	err := wait.PollUntilContextCancel(ctx, time.Millisecond*200, true, func(ctx context.Context) (done bool, err error) {
		c, err := cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, name, metav1.GetOptions{})
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
	})
	if err != nil {
		t.Error("Failed waiting for Certificate to have Issuing condition")
	}
}

func selfSignCertificateWithNotBeforeAfter(t *testing.T, pkData []byte, spec *cmapi.Certificate, notBefore, notAfter time.Time) []byte {
	t.Helper()
	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		t.Fatal(err)
	}

	template, err := pki.CertificateTemplateFromCertificate(spec)
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

// applyTestCondition applies a 'random' test condition to the given
// certificate. This can be used to force a run of a reconciler that is
// triggered on certificate events.
func applyTestCondition(t *testing.T, ctx context.Context, cert *cmapi.Certificate, client cmclient.Interface) {
	t.Helper()
	testCond := cmapi.CertificateCondition{
		Type:    cmapi.CertificateConditionType("Test"),
		Reason:  "TestTwo",
		Message: fmt.Sprintf("Test-%s", time.Now().Truncate(time.Second).String()),
		Status:  cmmeta.ConditionUnknown,
	}
	// Patch instead of update as there might be conflicts here due to
	// trigger controller picking up the cert and adding Issuing condition
	// in between.
	statusUpdate := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: cert.Name, Namespace: cert.Namespace},
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.CertificateKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		Status: cmapi.CertificateStatus{
			Conditions: []cmapi.CertificateCondition{testCond},
		},
	}
	statusUpdateJson, err := json.Marshal(statusUpdate)
	if err != nil {
		t.Errorf("failed to marshal cert data: %v", err)
	}
	_, err = client.CertmanagerV1().Certificates(cert.Namespace).Patch(
		ctx, cert.Name, types.ApplyPatchType, statusUpdateJson, metav1.PatchOptions{FieldManager: "test", Force: ptr.To(true)},
		"status",
	)
	if err != nil {
		t.Fatalf("Failed to apply test condition: %v", err)
	}
}
