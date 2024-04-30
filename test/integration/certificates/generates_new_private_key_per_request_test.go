/*
Copyright 2022 The cert-manager Authors.

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
	"crypto"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/keymanager"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/readiness"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/requestmanager"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/revisionmanager"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/trigger"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func TestGeneratesNewPrivateKeyIfMarkedInvalidRequest(t *testing.T) {
	namespace := "default"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build, instantiate and run all required controllers
	stopControllers := runAllControllers(t, config)
	defer stopControllers()

	_, _, cmCl, _, _ := framework.NewClients(t, config)
	crt, err := cmCl.CertmanagerV1().Certificates(namespace).Create(ctx, &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "testcrt"},
		Spec: cmapi.CertificateSpec{
			SecretName: "testsecret",
			DNSNames:   []string{"something"},
			IssuerRef: cmmeta.ObjectReference{
				Name: "issuer",
			},
			PrivateKey: &cmapi.CertificatePrivateKey{
				// This doesn't actually make any difference in this test case because there is no existing private
				// key, meaning there's no private key to re-use.
				RotationPolicy: cmapi.RotationPolicyAlways,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	var firstReq *cmapi.CertificateRequest
	if err := wait.PollUntilContextTimeout(ctx, time.Millisecond*500, time.Second*10, true, func(ctx context.Context) (bool, error) {
		reqs, err := cmCl.CertmanagerV1().CertificateRequests(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		if len(reqs.Items) > 1 {
			return false, fmt.Errorf("invalid state, expected only one CR but got %d", len(reqs.Items))
		}

		if len(reqs.Items) == 0 {
			return false, nil
		}

		firstReq = &reqs.Items[0]
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	t.Logf("Found CertificateRequest")
	// Remember the CSR data used for the first request so we can compare it later
	originalCSR := firstReq.Spec.Request

	// Mark the CSR as 'InvalidRequest'
	apiutil.SetCertificateRequestCondition(firstReq, cmapi.CertificateRequestConditionInvalidRequest, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonFailed, "manually failed")
	_, err = cmCl.CertmanagerV1().CertificateRequests(firstReq.Namespace).UpdateStatus(ctx, firstReq, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("failed to mark CertificateRequest as Failed: %v", err)
	}
	t.Log("Marked CertificateRequest as InvalidRequest")

	// Wait for Certificate to be marked as Failed
	if err := wait.PollUntilContextTimeout(ctx, time.Millisecond*500, time.Second*50, true, func(ctx context.Context) (bool, error) {
		crt, err := cmCl.CertmanagerV1().Certificates(crt.Namespace).Get(ctx, crt.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		return apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionReady).Status == cmmeta.ConditionFalse &&
			apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing).Status == cmmeta.ConditionFalse, nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("Issuance acknowledged as failed as expected")
	t.Logf("Triggering new issuance")

	crt, err = cmCl.CertmanagerV1().Certificates(crt.Namespace).Get(ctx, crt.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get certificate: %v", err)
	}

	apiutil.SetCertificateCondition(crt, crt.Generation, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "ManualTrigger", "triggered by test case manually")
	crt, err = cmCl.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("failed to update certificate: %v", err)
	}

	var secondReq cmapi.CertificateRequest
	if err := wait.PollUntilContextTimeout(ctx, time.Millisecond*500, time.Second*10, true, func(ctx context.Context) (bool, error) {
		reqs, err := cmCl.CertmanagerV1().CertificateRequests(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		for _, req := range reqs.Items {
			// We expect a new request to be created (with the same name as the first request)
			// and the old request to be deleted. We can check this by comparing the UID of the
			// first request with the UID of the second request.
			if req.UID == firstReq.UID {
				continue
			}

			secondReq = req
			return true, nil
		}

		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("Second request created successfully")
	t.Logf("Comparing public keys of first and second request...")

	csr1, err := pki.DecodeX509CertificateRequestBytes(originalCSR)
	if err != nil {
		t.Fatalf("failed to parse first CSR: %v", err)
	}
	csr2, err := pki.DecodeX509CertificateRequestBytes(secondReq.Spec.Request)
	if err != nil {
		t.Fatalf("failed to parse first CSR: %v", err)
	}

	pk1 := csr1.PublicKey.(crypto.PublicKey)
	pk2 := csr2.PublicKey.(crypto.PublicKey)

	if pk1.(comparablePublicKey).Equal(pk2) {
		t.Errorf("expected the two requests to have been signed by distinct private keys, but the private key has been reused")
	}
}

// Runs all Certificate controllers to exercise the full flow of attempting issuance.
// Checks to make sure that when an issuance fails and is re-attempted, a new private key is used
// to sign the second request.
func TestGeneratesNewPrivateKeyPerRequest(t *testing.T) {
	namespace := "default"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build, instantiate and run all required controllers
	stopControllers := runAllControllers(t, config)
	defer stopControllers()

	_, _, cmCl, _, _ := framework.NewClients(t, config)
	crt, err := cmCl.CertmanagerV1().Certificates(namespace).Create(ctx, &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "testcrt"},
		Spec: cmapi.CertificateSpec{
			SecretName: "testsecret",
			DNSNames:   []string{"something"},
			IssuerRef: cmmeta.ObjectReference{
				Name: "issuer",
			},
			PrivateKey: &cmapi.CertificatePrivateKey{
				// This doesn't actually make any difference in this test case because there is no existing private
				// key, meaning there's no private key to re-use.
				RotationPolicy: cmapi.RotationPolicyAlways,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	var firstReq *cmapi.CertificateRequest
	if err := wait.PollUntilContextTimeout(ctx, time.Millisecond*500, time.Second*10, true, func(ctx context.Context) (bool, error) {
		reqs, err := cmCl.CertmanagerV1().CertificateRequests(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		if len(reqs.Items) > 1 {
			return false, fmt.Errorf("invalid state, expected only one CR but got %d", len(reqs.Items))
		}

		if len(reqs.Items) == 0 {
			return false, nil
		}

		firstReq = &reqs.Items[0]
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	t.Logf("Found CertificateRequest")
	// Remember the CSR data used for the first request so we can compare it later
	originalCSR := firstReq.Spec.Request

	// Mark the CSR as 'Failed'
	apiutil.SetCertificateRequestCondition(firstReq, cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, "manually failed")
	_, err = cmCl.CertmanagerV1().CertificateRequests(firstReq.Namespace).UpdateStatus(ctx, firstReq, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("failed to mark CertificateRequest as Failed: %v", err)
	}
	t.Log("Marked CertificateRequest as Failed")

	// Wait for Certificate to be marked as Failed
	if err := wait.PollUntilContextTimeout(ctx, time.Millisecond*500, time.Second*50, true, func(ctx context.Context) (bool, error) {
		crt, err := cmCl.CertmanagerV1().Certificates(crt.Namespace).Get(ctx, crt.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		return apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionReady).Status == cmmeta.ConditionFalse &&
			apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing).Status == cmmeta.ConditionFalse, nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("Issuance acknowledged as failed as expected")
	t.Logf("Triggering new issuance")

	crt, err = cmCl.CertmanagerV1().Certificates(crt.Namespace).Get(ctx, crt.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get certificate: %v", err)
	}

	apiutil.SetCertificateCondition(crt, crt.Generation, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "ManualTrigger", "triggered by test case manually")
	crt, err = cmCl.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("failed to update certificate: %v", err)
	}

	var secondReq cmapi.CertificateRequest
	if err := wait.PollUntilContextTimeout(ctx, time.Millisecond*500, time.Second*10, true, func(ctx context.Context) (bool, error) {
		reqs, err := cmCl.CertmanagerV1().CertificateRequests(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		for _, req := range reqs.Items {
			// We expect a new request to be created (with the same name as the first request)
			// and the old request to be deleted. We can check this by comparing the UID of the
			// first request with the UID of the second request.
			if req.UID == firstReq.UID {
				continue
			}

			secondReq = req
			return true, nil
		}

		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("Second request created successfully")
	t.Logf("Comparing public keys of first and second request...")

	csr1, err := pki.DecodeX509CertificateRequestBytes(originalCSR)
	if err != nil {
		t.Fatalf("failed to parse first CSR: %v", err)
	}
	csr2, err := pki.DecodeX509CertificateRequestBytes(secondReq.Spec.Request)
	if err != nil {
		t.Fatalf("failed to parse first CSR: %v", err)
	}

	pk1 := csr1.PublicKey.(crypto.PublicKey)
	pk2 := csr2.PublicKey.(crypto.PublicKey)

	if pk1.(comparablePublicKey).Equal(pk2) {
		t.Errorf("expected the two requests to have been signed by distinct private keys, but the private key has been reused")
	}
}

type comparablePublicKey interface {
	Equal(crypto.PublicKey) bool
}

func runAllControllers(t *testing.T, config *rest.Config) framework.StopFunc {
	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)
	log := logf.Log
	clock := clock.RealClock{}
	metrics := metrics.New(log, clock)
	controllerContext := controllerpkg.Context{
		Client:                    kubeClient,
		Scheme:                    scheme,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmCl,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Metrics: metrics,
			Clock:   clock,
		},
		Recorder:     framework.NewEventRecorder(t, scheme),
		FieldManager: "cert-manager-certificates-issuing-test",
	}

	// TODO: set field mananager before calling each of those- is that what we do in actual code?
	revCtrl, revQueue, revMustSync := revisionmanager.NewController(log, &controllerContext)
	revisionManager := controllerpkg.NewController("revisionmanager_controller", metrics, revCtrl.ProcessItem, revMustSync, nil, revQueue)

	readyCtrl, readyQueue, readyMustSync := readiness.NewController(log, &controllerContext, policies.NewReadinessPolicyChain(clock), pki.RenewalTime, readiness.BuildReadyConditionFromChain)
	readinessManager := controllerpkg.NewController("readiness_controller", metrics, readyCtrl.ProcessItem, readyMustSync, nil, readyQueue)

	issueCtrl, issueQueue, issueMustSync := issuing.NewController(log, &controllerContext)
	issueManager := controllerpkg.NewController("issuing_controller", metrics, issueCtrl.ProcessItem, issueMustSync, nil, issueQueue)

	reqCtrl, reqQueue, reqMustSync := requestmanager.NewController(log, &controllerContext)
	requestManager := controllerpkg.NewController("requestmanager_controller", metrics, reqCtrl.ProcessItem, reqMustSync, nil, reqQueue)

	keyCtrl, keyQueue, keyMustSync := keymanager.NewController(log, &controllerContext)
	keyManager := controllerpkg.NewController("keymanager_controller", metrics, keyCtrl.ProcessItem, keyMustSync, nil, keyQueue)

	triggerCtrl, triggerQueue, triggerMustSync := trigger.NewController(log, &controllerContext, policies.NewTriggerPolicyChain(clock).Evaluate)
	triggerManager := controllerpkg.NewController("trigger_controller", metrics, triggerCtrl.ProcessItem, triggerMustSync, nil, triggerQueue)

	return framework.StartInformersAndControllers(t, factory, cmFactory, revisionManager, requestManager, keyManager, triggerManager, readinessManager, issueManager)
}
