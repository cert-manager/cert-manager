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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"

	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/test/integration/framework"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// Test_CleanupPolicyChange tests change state of issuerRef on created Secret
// when certificate cleanupPolicy is changed.

func Test_CleanupPolicyChange(t *testing.T) {
	const (
		fieldManager = "cert-manager-cleanup-policy-test"
	)

	t.Log("starting controller with default secret cleanup policy set to Never")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	kubeClient, factory, cmClient, cmFactory := framework.NewClients(t, config)
	controllerOptions := controllerpkg.CertificateOptions{
		EnableOwnerRef:             false,
		DefaultSecretCleanupPolicy: certmanager.CleanupPolicyNever,
	}
	ctrl, queue, mustSync := issuing.NewController(logf.Log, kubeClient, cmClient,
		factory, cmFactory, framework.NewEventRecorder(t), clock.RealClock{},
		controllerOptions, fieldManager,
	)
	c := controllerpkg.NewController(ctx, fieldManager, metrics.New(logf.Log, clock.RealClock{}), ctrl.ProcessItem, mustSync, nil, queue)
	stopControllerNoOwnerRef := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer func() {
		if stopControllerNoOwnerRef != nil {
			stopControllerNoOwnerRef()
		}
	}()

	t.Log("creating a Secret and Certificate which does not need issuance")
	ns, err := kubeClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "owner-reference-test"}}, metav1.CreateOptions{})
	require.NoError(t, err)
	crt := gen.Certificate("owner-reference-test",
		gen.SetCertificateNamespace(ns.Name),
		gen.SetCertificateCommonName("my-common-name"),
		gen.SetCertificateDNSNames("example.com", "foo.example.com"),
		gen.SetCertificateIPs("1.2.3.4", "5.6.7.8"),
		gen.SetCertificateURIs("spiffe://hello.world"),
		gen.SetCertificateKeyAlgorithm(cmapi.RSAKeyAlgorithm),
		gen.SetCertificateKeySize(2048),
		gen.SetCertificateSecretName("cert-manager-issuing-test-secret"),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "testissuer", Group: "foo.io", Kind: "Issuer"}),
	)
	bundle := testcrypto.MustCreateCryptoBundle(t, crt, &clock.RealClock{})
	secret, err := kubeClient.CoreV1().Secrets(ns.Name).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: crt.Spec.SecretName},
		Data: map[string][]byte{
			"ca.crt":  bundle.CertBytes,
			"tls.crt": bundle.CertBytes,
			"tls.key": bundle.PrivateKeyBytes,
		},
	}, metav1.CreateOptions{FieldManager: fieldManager})
	require.NoError(t, err)
	crt, err = cmClient.CertmanagerV1().Certificates(ns.Name).Create(ctx, crt, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Log("ensure Certificate does not gain Issuing condition")
	require.Never(t, func() bool {
		crt, err = cmClient.CertmanagerV1().Certificates(ns.Name).Get(ctx, crt.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue})
	}, time.Second*3, time.Millisecond*10, "expected Certificate to not gain Issuing condition")

	t.Log("change Certificate cleanupPolicy to onDelete")
	crt.Spec.CleanupPolicy = certmanager.CleanupPolicyOnDelete
	crt, err = cmClient.CertmanagerV1().Certificates(ns.Name).Update(ctx, crt, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		fmt.Println(secret.OwnerReferences)
		return apiequality.Semantic.DeepEqual(secret.OwnerReferences, []metav1.OwnerReference{*metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate"))})
	}, time.Second*10, time.Millisecond*10, "expected Secret to have owner reference to Certificate added: %#+v", secret.OwnerReferences)

	t.Log("change Certificate cleanupPolicy to Never")
	crt.Spec.CleanupPolicy = certmanager.CleanupPolicyNever
	crt, err = cmClient.CertmanagerV1().Certificates(ns.Name).Update(ctx, crt, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return len(secret.OwnerReferences) == 0
	}, time.Second*10, time.Millisecond*10, "expected Secret cannot have owner reference to Certificate")

	t.Log("restarting controller with default secret cleanup policy set to OnDelete")
	stopControllerNoOwnerRef()
	kubeClient, factory, cmClient, cmFactory = framework.NewClients(t, config)
	stopControllerNoOwnerRef = nil
	controllerOptions.DefaultSecretCleanupPolicy = certmanager.CleanupPolicyOnDelete
	ctrl, queue, mustSync = issuing.NewController(logf.Log, kubeClient, cmClient,
		factory, cmFactory, framework.NewEventRecorder(t), clock.RealClock{},
		controllerOptions, fieldManager,
	)
	c = controllerpkg.NewController(ctx, fieldManager, metrics.New(logf.Log, clock.RealClock{}), ctrl.ProcessItem, mustSync, nil, queue)
	stopControllerOwnerRef := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopControllerOwnerRef()

	t.Log("remove Certificate cleanupPolicy")
	crt.Spec.CleanupPolicy = ""
	crt, err = cmClient.CertmanagerV1().Certificates(ns.Name).Update(ctx, crt, metav1.UpdateOptions{})

	t.Log("waiting for owner reference to be set")
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return apiequality.Semantic.DeepEqual(secret.OwnerReferences, []metav1.OwnerReference{*metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate"))})
	}, time.Second*10, time.Millisecond*10, "expected Secret to have owner reference to Certificate added: %#+v", secret.OwnerReferences)

	t.Log("change Certificate cleanupPolicy to Never")
	crt.Spec.CleanupPolicy = certmanager.CleanupPolicyNever
	crt, err = cmClient.CertmanagerV1().Certificates(ns.Name).Update(ctx, crt, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return len(secret.OwnerReferences) == 0
	}, time.Second*10, time.Millisecond*10, "expected Secret cannot have owner reference to Certificate")

	t.Log("change Certificate cleanupPolicy to onDelete")
	crt.Spec.CleanupPolicy = certmanager.CleanupPolicyOnDelete
	crt, err = cmClient.CertmanagerV1().Certificates(ns.Name).Update(ctx, crt, metav1.UpdateOptions{})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		secret, err = kubeClient.CoreV1().Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		fmt.Println(secret.OwnerReferences)
		return apiequality.Semantic.DeepEqual(secret.OwnerReferences, []metav1.OwnerReference{*metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate"))})
	}, time.Second*10, time.Millisecond*10, "expected Secret to have owner reference to Certificate added: %#+v", secret.OwnerReferences)

}
