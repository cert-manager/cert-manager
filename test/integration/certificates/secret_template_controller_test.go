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

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificates/secrettemplate"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/integration/framework"
)

// Test_SecretTemplateController performs a basic check to ensure that values
// in a Certificate's SecretTemplate will be copied to the target Secret- when
// they are both added and deleted.
func Test_SecretTemplateController(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build, instantiate and run the trigger controller.
	kubeClient, factory, cmCl, cmFactory := framework.NewClients(t, config)

	namespace := "testns"

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	ctrl, queue, mustSync := secrettemplate.NewController(
		logf.Log, kubeClient, config,
		cmCl, factory, cmFactory,
		controllerpkg.CertificateOptions{
			EnableOwnerRef: true,
		},
	)

	c := controllerpkg.NewController(
		ctx,
		"secrettemplate_test",
		metrics.New(logf.Log, clock.RealClock{}),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	// Create a Certificate resource and set the Ready and Issuing condition to True.
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

	// Create certificate to populate Secret.
	sk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	skBytes := pki.EncodePKCS1PrivateKey(sk)
	// Create an X.509 cert
	x509CertBytes := selfSignCertificateWithNotBeforeAfter(t, skBytes, cert, time.Now().Add(-time.Minute), time.Now().Add(time.Minute))
	// Create a Secret with the X.509 cert
	_, err = kubeClient.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey: x509CertBytes,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Set the conditions of the Certificate to be Ready=true and Issuing=false.
	cert.Status.Conditions = []cmapi.CertificateCondition{
		{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue},
		{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse},
	}
	cert, err = cmCl.CertmanagerV1().Certificates(namespace).UpdateStatus(ctx, cert, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	annotations := map[string]string{"annotation-1": "abc", "annotation-2": "123"}
	labels := map[string]string{"labels-1": "abc", "labels-2": "123"}

	// Add labels and annotations to the SecretTemplate.
	cert.Spec.SecretTemplate = &cmapi.CertificateSecretTemplate{
		Annotations: annotations,
		Labels:      labels,
	}
	cert, err = cmCl.CertmanagerV1().Certificates(namespace).Update(ctx, cert, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the Annotations and Labels to be observed on the Secret.
	err = wait.PollImmediateUntil(time.Millisecond*100, func() (done bool, err error) {
		secret, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, "example", metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Secret resource, retrying: %s", err)
			return false, nil
		}
		for k, v := range annotations {
			if gotV, ok := secret.Annotations[k]; !ok || v != gotV {
				return false, nil
			}
		}
		for k, v := range labels {
			if gotV, ok := secret.Labels[k]; !ok || v != gotV {
				return false, nil
			}
		}
		return true, nil
	}, ctx.Done())
	if err != nil {
		t.Fatal(err)
	}

	// Remove labels and annotations from the SecretTemplate.
	cert.Spec.SecretTemplate = nil
	cert, err = cmCl.CertmanagerV1().Certificates(namespace).Update(ctx, cert, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait for the Annotations and Labels to be removed from the Secret.
	err = wait.PollImmediateUntil(time.Millisecond*100, func() (done bool, err error) {
		secret, err := kubeClient.CoreV1().Secrets(namespace).Get(ctx, "example", metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Secret resource, retrying: %s", err)
			return false, nil
		}
		for k := range annotations {
			if _, ok := secret.Annotations[k]; ok {
				return false, nil
			}
		}
		for k := range labels {
			if _, ok := secret.Labels[k]; ok {
				return false, nil
			}
		}
		return true, nil
	}, ctx.Done())
	if err != nil {
		t.Fatal(err)
	}
}
