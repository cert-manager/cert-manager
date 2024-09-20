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

package acme

import (
	"context"
	"fmt"
	"testing"
	"time"

	acmeapi "golang.org/x/crypto/acme"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	accountstest "github.com/cert-manager/cert-manager/pkg/acme/accounts/test"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/acmeorders"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestAcmeOrdersController(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Create clients and informer factories for Kubernetes API and
	// cert-manager.
	kubeClient, factory, cmCl, cmFactory, scheme := framework.NewClients(t, config)

	// some test values
	var (
		testName      = "acmetest"
		challengeType = "dns-01"
		authType      = "dns"
	)

	// Initial ACME authorization to be returned by GetAuthorization.
	auth := &acmeapi.Authorization{
		URI:    testName,
		Status: acmeapi.StatusPending,
		Challenges: []*acmeapi.Challenge{
			{
				Type:  challengeType,
				URI:   testName,
				Token: testName,
			},
		},
		Identifier: acmeapi.AuthzID{
			Type:  authType,
			Value: testName,
		},
	}
	// ACME order to be returned by calls to the fake registry.
	acmeOrder := &acmeapi.Order{
		URI: testName,
		Identifiers: []acmeapi.AuthzID{
			{
				Type:  authType,
				Value: testName,
			},
		},
		FinalizeURL: testName,
		AuthzURLs:   []string{testName},
		Status:      acmeapi.StatusPending,
	}
	// ACME client with stubbed methods to simulate a specific response from the
	// ACME server.
	acmeClient := &acmecl.FakeACME{
		FakeAuthorizeOrder: func(_ context.Context, _ []acmeapi.AuthzID, _ ...acmeapi.OrderOption) (*acmeapi.Order, error) {
			return acmeOrder, nil
		},
		FakeGetAuthorization: func(_ context.Context, _ string) (*acmeapi.Authorization, error) {
			return auth, nil
		},
		FakeGetOrder: func(_ context.Context, _ string) (*acmeapi.Order, error) {
			return acmeOrder, nil
		},
		FakeDNS01ChallengeRecord: func(_ string) (string, error) {
			return testName, nil
		},
		FakeCreateOrderCert: func(_ context.Context, _ string, _ []byte, _ bool) ([][]byte, string, error) {
			// A hack to ensure the status of the _ACME_ order gets set to valid
			// when we're finalizing the order.
			acmeOrder.Status = acmeapi.StatusValid
			return [][]byte{}, "", nil
		},
	}

	// Create a fake ACME registry with a GetClientFunc that returns the
	// acmeClient with the stubbed methods.
	accountRegistry := &accountstest.FakeRegistry{
		GetClientFunc: func(_ string) (acmecl.Interface, error) {
			return acmeClient, nil
		},
	}

	controllerContext := controllerpkg.Context{
		Client:                    kubeClient,
		Scheme:                    scheme,
		KubeSharedInformerFactory: factory,
		CMClient:                  cmCl,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Clock: clock.RealClock{},
			ACMEOptions: controllerpkg.ACMEOptions{
				AccountRegistry: accountRegistry,
			},
		},

		Recorder:     framework.NewEventRecorder(t, scheme),
		FieldManager: "cert-manager-orders-test",
	}

	// Create a new orders controller.
	ctrl, queue, mustSync, err := acmeorders.NewController(
		logf.Log,
		&controllerContext,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	c := controllerpkg.NewController(
		"orders_test",
		metrics.New(logf.Log, clock.RealClock{}),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)

	// Ensure the controller is started now and stopped after the tests.
	stopController := framework.StartInformersAndController(
		t,
		factory,
		cmFactory,
		c,
	)
	defer stopController()

	// Create a Namespace.
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testName}}
	if _, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	// Create an Issuer for Order.
	acmeIssuer := cmacme.ACMEIssuer{
		PrivateKey: cmmeta.SecretKeySelector{Key: testName},
		Server:     testName,
		Solvers: []cmacme.ACMEChallengeSolver{
			{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
						Email:    testName,
						APIToken: &cmmeta.SecretKeySelector{Key: testName},
					},
				},
			},
		},
	}
	acmeIssuer.PrivateKey.Name = testName
	acmeIssuer.Solvers[0].DNS01.Cloudflare.APIToken.Name = testName
	iss := gen.Issuer(testName,
		gen.SetIssuerNamespace(testName),
		gen.SetIssuerACME(acmeIssuer))

	_, err = cmCl.CertmanagerV1().Issuers(testName).Create(ctx, iss, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Test that a Challenge is created for a new Order.

	// Create an Order CR.
	order := gen.Order(testName,
		gen.SetOrderIssuer(cmmeta.ObjectReference{
			Name: testName,
		}),
		gen.SetOrderNamespace(testName),
		gen.SetOrderCsr([]byte(testName)),
		gen.SetOrderDNSNames(testName))

	order, err = cmCl.AcmeV1().Orders(testName).Create(ctx, order, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the Challenge to be created.
	var chal *cmacme.Challenge
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
		chals, err := cmCl.AcmeV1().Challenges(testName).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		l := len(chals.Items)
		// Challenge has not been created yet
		if l == 0 {
			return false, nil
		}
		// this should never happen
		if l > 1 {
			return false, fmt.Errorf("expected maximum 1 challenge, got %d", l)
		}
		// Check that the Challenge is owned by our Order.
		chal = &chals.Items[0]
		if !metav1.IsControlledBy(chal, order) {
			return false, fmt.Errorf("found an unexpected Challenge resource: %v", chal.Name)
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Test that in an edge case, where an ACME server is misbehaving and
	// despite Challenges being valid, the ACME order status is 'pending', we
	// re-queue the Order so that when the ACME order does become 'ready', we
	// finalize our Order and, in the success scenario, it eventually becomes
	// valid.
	// https://github.com/cert-manager/cert-manager/issues/2868

	// Set the Challenge state to valid, the status of the ACME order remains 'pending'.
	chal = chal.DeepCopy()
	chal.Status.State = cmacme.Valid
	_, err = cmCl.AcmeV1().Challenges(testName).UpdateStatus(ctx, chal, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Override the default requeue period.
	acmeorders.RequeuePeriod = time.Second * 2

	// Sit here for a little bit checking that the Order status remains pending
	// and also to verify that this test works.
	// TODO: instead of waiting for the Order to remain 'pending', we should use
	// Reason field on Order's status. Change this test once we are setting
	// Reasons on intermittent Order states.
	var pendingOrder *cmacme.Order
	startTime := time.Now()
	successful := false
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*200, true, func(ctx context.Context) (bool, error) {
		// Check if order has been pending for 2s (requeue period)
		if time.Since(startTime) > acmeorders.RequeuePeriod {
			successful = true
			return true, nil
		}

		pendingOrder, err = cmCl.AcmeV1().Orders(testName).Get(ctx, testName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if pendingOrder.Status.State != cmacme.Pending {
			return true, nil
		}
		return false, nil
	})
	switch {
	case err == nil && !successful:
		t.Fatalf("Expected Order to have pending status instead got: %v", pendingOrder.Status.State)
	case err == nil && successful:
		// this is the expected 'happy case'
	default:
		t.Fatal(err)
	}

	// Set status of the ACME order to 'ready'.
	acmeOrder.Status = acmeapi.StatusReady

	// Wait for the status of the Order to become Valid.
	err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
		o, err := cmCl.AcmeV1().Orders(testName).Get(ctx, testName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		// not valid yet
		if o.Status.State != cmacme.Valid {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
