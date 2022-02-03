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
	"testing"
	"time"

	"github.com/go-logr/logr"
	logtesting "github.com/go-logr/logr/testing"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/cert-manager/cert-manager/pkg/webhook/authority"
	"github.com/cert-manager/cert-manager/pkg/webhook/server/tls"
	"github.com/cert-manager/cert-manager/test/integration/framework"
)

// Ensure that when the source is running against an apiserver, it bootstraps
// a CA and signs a valid certificate.
func TestDynamicSource_Bootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(logr.NewContext(context.Background(), logtesting.NewTestLogger(t)), time.Second*40)
	defer cancel()

	config, stop := framework.RunControlPlane(t, ctx)
	defer stop()

	kubeClient, _, _, _ := framework.NewClients(t, config)

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
		if err := source.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("Unexpected error running source: %v", err)
		}
	}()

	// allow the controller 5s to provision the Secret - this is far longer
	// than it should ever take.
	if err := wait.PollImmediateUntil(time.Millisecond*500, func() (done bool, err error) {
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
	}, ctx.Done()); err != nil {
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

	kubeClient, _, _, _ := framework.NewClients(t, config)

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
		if err := source.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("Unexpected error running source: %v", err)
		}
	}()

	var serialNumber *big.Int
	// allow the controller 5s to provision the Secret - this is far longer
	// than it should ever take.
	if err := wait.PollImmediateUntil(time.Millisecond*500, func() (done bool, err error) {
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
	}, ctx.Done()); err != nil {
		t.Errorf("Failed waiting for source to return a certificate: %v", err)
		return
	}

	cl := kubernetes.NewForConfigOrDie(config)
	if err := cl.CoreV1().Secrets(source.Authority.SecretNamespace).Delete(ctx, source.Authority.SecretName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("Failed to delete CA secret: %v", err)
	}

	// wait for the serving certificate to have a new serial number (which
	// indicates it has been regenerated)
	if err := wait.PollImmediateUntil(time.Millisecond*500, func() (done bool, err error) {
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
	}, ctx.Done()); err != nil {
		t.Errorf("Failed waiting for source to return a certificate: %v", err)
		return
	}
}
