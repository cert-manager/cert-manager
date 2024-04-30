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

package webhook

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	logtesting "github.com/go-logr/logr/testing"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	"github.com/cert-manager/cert-manager/pkg/server/tls"
	"github.com/cert-manager/cert-manager/pkg/server/tls/authority"
	"github.com/cert-manager/cert-manager/test/apiserver"
)

// Ensure that when the source is running against an apiserver, it bootstraps
// a CA and signs a valid certificate.
func TestDynamicSource_Bootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(logr.NewContext(context.Background(), logtesting.NewTestLogger(t)), time.Second*40)
	defer cancel()

	config, stop := framework.RunControlPlane(t, ctx)
	defer stop()

	kubeClient, _, _, _, _ := framework.NewClients(t, config)

	namespace := "testns"

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	source := tls.DynamicSource{
		DNSNames: []string{"example.com"},
		Authority: &authority.DynamicAuthority{
			SecretNamespace: namespace,
			SecretName:      "testsecret",
			RESTConfig:      config,
		},
	}
	errCh := make(chan error)
	defer func() {
		cancel()
		err := <-errCh
		if err != nil {
			t.Fatal(err)
		}
	}()
	// run the dynamic authority controller in the background
	go func() {
		defer close(errCh)
		if err := source.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("Unexpected error running source: %v", err)
		}
	}()

	// allow the controller 5s to provision the Secret - this is far longer
	// than it should ever take.
	if err := wait.PollUntilContextCancel(ctx, time.Millisecond*500, true, func(ctx context.Context) (done bool, err error) {
		cert, err := source.GetCertificate(nil)
		if err == tls.ErrNotAvailable {
			t.Logf("GetCertificate has no certificate available, waiting...")
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if cert == nil {
			t.Errorf("Returned certificate is nil")
		}
		t.Logf("Got non-nil certificate from dynamic source")
		return true, nil
	}); err != nil {
		t.Errorf("Failed waiting for source to return a certificate: %v", err)
		return
	}
}

// Ensure that when the source is running against an apiserver, it bootstraps
// a CA and signs a valid certificate.
func TestDynamicSource_CARotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(logr.NewContext(context.Background(), logtesting.NewTestLogger(t)), time.Second*40)
	defer cancel()

	config, stop := framework.RunControlPlane(t, ctx)
	defer stop()

	kubeClient, _, _, _, _ := framework.NewClients(t, config)

	secretName := "testsecret"
	secretNamespace := "testns"

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: secretNamespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	source := tls.DynamicSource{
		DNSNames: []string{"example.com"},
		Authority: &authority.DynamicAuthority{
			SecretName:      secretName,
			SecretNamespace: secretNamespace,
			RESTConfig:      config,
		},
	}
	errCh := make(chan error)
	defer func() {
		cancel()
		err := <-errCh
		if err != nil {
			t.Fatal(err)
		}
	}()
	// run the dynamic authority controller in the background
	go func() {
		defer close(errCh)
		if err := source.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("Unexpected error running source: %v", err)
		}
	}()

	var serialNumber *big.Int
	// allow the controller 5s to provision the Secret - this is far longer
	// than it should ever take.
	if err := wait.PollUntilContextCancel(ctx, time.Millisecond*500, true, func(ctx context.Context) (done bool, err error) {
		cert, err := source.GetCertificate(nil)
		if err == tls.ErrNotAvailable {
			t.Logf("GetCertificate has no certificate available, waiting...")
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if cert == nil {
			t.Fatalf("Returned certificate is nil")
		}
		t.Logf("Got non-nil certificate from dynamic source")

		x509cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("Failed to decode certificate: %v", err)
		}

		serialNumber = x509cert.SerialNumber
		return true, nil
	}); err != nil {
		t.Errorf("Failed waiting for source to return a certificate: %v", err)
		return
	}

	cl := kubernetes.NewForConfigOrDie(config)
	if err := cl.CoreV1().Secrets(secretNamespace).Delete(ctx, secretName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("Failed to delete CA secret: %v", err)
	}

	// wait for the serving certificate to have a new serial number (which
	// indicates it has been regenerated)
	if err := wait.PollUntilContextCancel(ctx, time.Millisecond*500, true, func(ctx context.Context) (done bool, err error) {
		cert, err := source.GetCertificate(nil)
		if err == tls.ErrNotAvailable {
			t.Logf("GetCertificate has no certificate available, waiting...")
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if cert == nil {
			t.Fatalf("Returned certificate is nil")
		}
		t.Logf("Got non-nil certificate from dynamic source")

		x509cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("Failed to decode certificate: %v", err)
		}

		if serialNumber.Cmp(x509cert.SerialNumber) == 0 {
			t.Log("Certificate has not been regenerated, waiting...")
			return false, nil
		}

		return true, nil
	}); err != nil {
		t.Errorf("Failed waiting for source to return a certificate: %v", err)
		return
	}
}

// Make sure that controller-runtime leader election does not cause the authority
// to not start on non-leader managers.
func TestDynamicSource_leaderelection(t *testing.T) {
	const nrManagers = 2 // number of managers to start for this test

	ctx, cancel := context.WithTimeout(logr.NewContext(context.Background(), logtesting.NewTestLogger(t)), time.Second*40)
	defer cancel()

	env, stop := apiserver.RunBareControlPlane(t)
	defer stop()

	var started int64

	gctx, cancel := context.WithCancel(ctx)
	defer cancel()
	group, gctx := errgroup.WithContext(gctx)

	for i := 0; i < nrManagers; i++ {
		i := i
		group.Go(func() error {
			mgr, err := manager.New(env.Config, manager.Options{
				Metrics:     server.Options{BindAddress: "0"},
				BaseContext: func() context.Context { return gctx },

				LeaderElection:          true,
				LeaderElectionID:        "leader-test",
				LeaderElectionNamespace: "default",
			})
			if err != nil {
				return err
			}

			if err := mgr.Add(&tls.DynamicSource{
				DNSNames: []string{"example.com"},
				Authority: &testAuthority{
					t:       t,
					id:      fmt.Sprintf("manager-%d", i),
					started: &started,
				},
			}); err != nil {
				return err
			}

			return mgr.Start(gctx)
		})
	}

	time.Sleep(4 * time.Second)

	cancel()

	if err := group.Wait(); err != nil {
		t.Fatal(err)
	}

	startCount := atomic.LoadInt64(&started)

	if startCount != nrManagers {
		t.Error("all managers should have started the authority, but only", startCount, "did")
	}
}

type testAuthority struct {
	t       *testing.T
	id      string
	started *int64
}

func (m *testAuthority) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil // context was cancelled, we are shutting down
	}

	m.t.Log("Starting authority with id", m.id)
	atomic.AddInt64(m.started, 1)
	<-ctx.Done()
	return nil
}

func (m *testAuthority) WatchRotation(ch chan<- struct{}) {}

func (m *testAuthority) StopWatchingRotation(ch chan<- struct{}) {}

func (m *testAuthority) Sign(template *x509.Certificate) (*x509.Certificate, error) {
	return nil, fmt.Errorf("not implemented")
}
