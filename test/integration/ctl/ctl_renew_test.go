/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/renew"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/integration/framework"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

// TestCtlRenew tests the renewal logic of the ctl CLI command against the
// cert-manager Issuing controller.
func TestCtlRenew(t *testing.T) {
	config, stopFn := framework.RunControlPlane(t)
	defer stopFn()

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*20)
	defer cancel()

	// Build, instantiate and run the issuing controller.
	kubeClient, _, cmCl, _ := framework.NewClients(t, config)

	var (
		crtName                  = "testcrt"
		namespace                = "testns"
		nextPrivateKeySecretName = "next-private-key-test-crt"
		secretName               = "test-crt-tls"
	)

	// Create a new private key
	sk, err := utilpki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	skBytes := utilpki.EncodePKCS1PrivateKey(sk)

	// Store new private key in secret
	_, err = kubeClient.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nextPrivateKeySecretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: skBytes,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create Certificate
	crt := gen.Certificate(crtName,
		gen.SetCertificateNamespace(namespace),
		gen.SetCertificateDNSNames("example.com"),
		gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
		gen.SetCertificateKeySize(2048),
		gen.SetCertificateSecretName(secretName),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "testissuer"}),
	)

	crt, err = cmCl.CertmanagerV1alpha2().Certificates(namespace).Create(ctx, crt, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Run ctl renew command and wait for ready
	streams, _, _, _ := genericclioptions.NewTestIOStreams()

	cmd := &renew.Options{
		Namespace:  "testns",
		CMClient:   cmCl,
		RestConfig: config,
		IOStreams:  streams,
	}

	if err := cmd.Run([]string{"testcrt"}); err != nil {
		t.Fatal(err)
	}

	// Wait for the Certificate to have the 'Issuing' condition set
	err = wait.Poll(time.Millisecond*100, time.Second*5, func() (done bool, err error) {
		crt, err = cmCl.CertmanagerV1alpha2().Certificates(namespace).Get(ctx, crtName, metav1.GetOptions{})
		if err != nil {
			t.Logf("Failed to fetch Certificate resource, retrying: %v", err)
			return false, nil
		}

		if cond := apiutil.GetCertificateCondition(crt, cmapi.CertificateConditionIssuing); cond == nil || cond.Status != cmmeta.ConditionTrue {
			t.Logf("Certificate does not have expected condition, got=%#v", cond)
			return false, nil
		}

		return true, nil
	})

	if err != nil {
		t.Fatalf("Failed to wait for final state: %+v", crt)
	}
}
