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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/server/tls/authority"
)

// Tests for the dynamic authority functionality to ensure it properly handles
// deletion, updates and creates on the 'watched' Secret resource.

// Ensure that when the controller is running against an empty API server, it
// creates and stores a new CA keypair.
func TestDynamicAuthority_Bootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(logr.NewContext(context.Background(), testr.New(t)), time.Second*40)
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

	auth := authority.DynamicAuthority{
		SecretNamespace: namespace,
		SecretName:      "testsecret",
		RESTConfig:      config,
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
		if err := auth.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("Unexpected error running authority: %v", err)
		}
	}()

	cl := kubernetes.NewForConfigOrDie(config)
	// allow the controller to provision the Secret
	if err := wait.PollUntilContextCancel(ctx, time.Millisecond*500, true, authoritySecretReadyConditionFunc(t, cl, auth.SecretNamespace, auth.SecretName)); err != nil {
		t.Errorf("Failed waiting for Secret to contain valid certificate: %v", err)
		return
	}
}

// Ensures that when the controller is running and the CA Secret is deleted,
// it is automatically recreated within a bounded amount of time.
func TestDynamicAuthority_Recreates(t *testing.T) {
	ctx, cancel := context.WithTimeout(logr.NewContext(context.Background(), testr.New(t)), time.Second*40)
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

	auth := authority.DynamicAuthority{
		SecretNamespace: namespace,
		SecretName:      "testsecret",
		RESTConfig:      config,
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
		if err := auth.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("Unexpected error running authority: %v", err)
		}
	}()

	cl := kubernetes.NewForConfigOrDie(config)
	// allow the controller to provision the Secret
	if err := wait.PollUntilContextCancel(ctx, time.Millisecond*500, true, authoritySecretReadyConditionFunc(t, cl, auth.SecretNamespace, auth.SecretName)); err != nil {
		t.Errorf("Failed waiting for Secret to contain valid certificate: %v", err)
		return
	}

	t.Logf("Secret resource has been provisioned, deleting to ensure it is recreated")
	if err := cl.CoreV1().Secrets(auth.SecretNamespace).Delete(ctx, auth.SecretName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}

	// allow the controller to provision the Secret again
	if err := wait.PollUntilContextCancel(ctx, time.Millisecond*500, true, authoritySecretReadyConditionFunc(t, cl, auth.SecretNamespace, auth.SecretName)); err != nil {
		t.Errorf("Failed waiting for Secret to be recreated: %v", err)
		return
	}
}

// authoritySecretReadyConditionFunc will check a named Secret resource and
// check if it contains a valid CA keypair used by the authority.
// This can be used with the `k8s.io/apimachinery/pkg/util/wait` package.
func authoritySecretReadyConditionFunc(t *testing.T, cl kubernetes.Interface, namespace, name string) wait.ConditionWithContextFunc {
	return func(ctx context.Context) (done bool, err error) {
		s, err := cl.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			t.Logf("Secret resource %s/%s does not yet exist, waiting...", namespace, name)
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if err := ensureSecretDataValid(s); err != nil {
			t.Logf("Secret resource does not contain a valid keypair yet: %v, waiting...", err)
			return false, nil
		}
		return true, nil
	}
}

// ensureSecretDataValid will check the contents of the given Secret to ensure
// it is valid to use as a CA for the dynamic authority.
func ensureSecretDataValid(s *corev1.Secret) error {
	if s.Data == nil {
		return fmt.Errorf("secret contains no data")
	}
	caData := s.Data[cmmeta.TLSCAKey]
	pkData := s.Data[corev1.TLSPrivateKeyKey]
	certData := s.Data[corev1.TLSCertKey]
	if len(caData) == 0 || len(pkData) == 0 || len(certData) == 0 {
		return fmt.Errorf("missing data in CA secret")
	}
	// ensure that the ca.crt and tls.crt keys are equal
	if !bytes.Equal(caData, certData) {
		return fmt.Errorf("expected Secret to contains a self-signed root but ca.crt and tls.crt differ")
	}
	cert, err := tls.X509KeyPair(certData, pkData)
	if err != nil {
		return fmt.Errorf("failed to parse data in CA secret: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("internal error parsing x509 certificate: %w", err)
	}
	if !x509Cert.IsCA {
		return fmt.Errorf("stored certificate is not marked as a CA")
	}
	return nil
}
