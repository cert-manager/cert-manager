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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/duplicatesecrets"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/test/integration/framework"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// TestIssuingController performs a basic test to ensure that the issuing
// TODO:
func Test_DuplicateSecrets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	kubeClient, factory, cmCl, cmFactory := framework.NewClients(t, config)

	ctrl, queue, mustSync := duplicatesecrets.NewController(logf.Log, cmCl,
		factory, cmFactory, "cert-manage-certificates-duplicatesecrets-test")
	c := controllerpkg.NewController(
		ctx,
		"duplicatesecrets_test",
		metrics.New(logf.Log, clock.RealClock{}),
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	var (
		namespace  = "testns"
		secretName = "test-crt-tls"
	)

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Create 2 Certificates with the same Secret name
	crt1 := gen.Certificate("1",
		gen.SetCertificateNamespace(namespace),
		gen.SetCertificateCommonName("my-common-name"),
		gen.SetCertificateSecretName(secretName),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "testissuer", Group: "foo.io", Kind: "Issuer"}),
	)
	crt2 := gen.CertificateFrom(crt1, gen.SetCertificateName("2"))
	crt3 := gen.CertificateFrom(crt1, gen.SetCertificateName("3"))

	crt1, err = cmCl.CertmanagerV1().Certificates(namespace).Create(ctx, crt1, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	crt2, err = cmCl.CertmanagerV1().Certificates(namespace).Create(ctx, crt2, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if err := wait.PollImmediateUntilWithContext(ctx, time.Millisecond*100, func(ctx context.Context) (bool, error) {
		crt1, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, "1", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		cond := apiutil.GetCertificateCondition(crt1, cmapi.CertificateConditionDuplicateSecretName)
		if !(cond != nil && cond.Status == cmmeta.ConditionTrue && cond.Reason == "2") {
			return false, nil
		}

		crt2, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, "2", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		cond = apiutil.GetCertificateCondition(crt2, cmapi.CertificateConditionDuplicateSecretName)
		if !(cond != nil && cond.Status == cmmeta.ConditionTrue && cond.Reason == "1") {
			return false, nil
		}

		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	// A third Certificate with the same Secret name should have all conditions
	// set.
	crt3, err = cmCl.CertmanagerV1().Certificates(namespace).Create(ctx, crt3, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if err := wait.PollImmediateUntilWithContext(ctx, time.Millisecond*100, func(ctx context.Context) (bool, error) {
		crt1, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, "1", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		crt2, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, "2", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		crt3, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, "3", metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		cond := apiutil.GetCertificateCondition(crt1, cmapi.CertificateConditionDuplicateSecretName)
		if !(cond != nil && cond.Status == cmmeta.ConditionTrue && cond.Reason == "2,3") {
			return false, nil
		}
		cond = apiutil.GetCertificateCondition(crt2, cmapi.CertificateConditionDuplicateSecretName)
		if !(cond != nil && cond.Status == cmmeta.ConditionTrue && cond.Reason == "1,3") {
			return false, nil
		}
		cond = apiutil.GetCertificateCondition(crt3, cmapi.CertificateConditionDuplicateSecretName)
		if !(cond != nil && cond.Status == cmmeta.ConditionTrue && cond.Reason == "1,2") {
			return false, nil
		}

		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	// Updating the Secret name of all Certificates so they are unique, should
	// remove the condition from all Certificates.
	crt1.Spec.SecretName = "1"
	crt2.Spec.SecretName = "2"
	crt3.Spec.SecretName = "3"

	crt1, err = cmCl.CertmanagerV1().Certificates(namespace).Update(ctx, crt1, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	crt2, err = cmCl.CertmanagerV1().Certificates(namespace).Update(ctx, crt2, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	crt3, err = cmCl.CertmanagerV1().Certificates(namespace).Update(ctx, crt3, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if err := wait.PollImmediateUntilWithContext(ctx, time.Millisecond*100, func(ctx context.Context) (bool, error) {
		crt1, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, "1", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		crt2, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, "2", metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		crt3, err = cmCl.CertmanagerV1().Certificates(namespace).Get(ctx, "3", metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		cond1 := apiutil.GetCertificateCondition(crt1, cmapi.CertificateConditionDuplicateSecretName)
		cond2 := apiutil.GetCertificateCondition(crt2, cmapi.CertificateConditionDuplicateSecretName)
		cond3 := apiutil.GetCertificateCondition(crt3, cmapi.CertificateConditionDuplicateSecretName)

		return cond1 == nil && cond2 == nil && cond3 == nil, nil
	}); err != nil {
		t.Fatal(err)
	}
}
