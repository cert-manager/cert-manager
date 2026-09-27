/*
Copyright 2026 The cert-manager Authors.

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
	"testing"
	"time"

	internalcertificates "github.com/cert-manager/cert-manager/internal/controller/certificates"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
)

// Test_StatusScalarApply ensures Certificate scalar status fields can be
// cleared by omission from ApplyStatus when owned solely by the applying
// field manager, and that omission does not clear fields owned by another
// manager.
//
// failedIssuanceAttempts and lastFailureTime are used as representative
// scalars. Conditions list-map multi-manager behavior is covered separately
// in condition_list_type_test.go.
func Test_StatusScalarApply(t *testing.T) {
	restConfig, stopFn := framework.RunControlPlane(t)
	t.Cleanup(stopFn)

	issuingRestConfig := util.RestConfigWithUserAgent(restConfig, "cert-manager-certificates-issuing")
	issuingFieldManager := util.PrefixFromUserAgent(issuingRestConfig.UserAgent)
	kubeClient, _, issuingCMClient, _, _ := framework.NewClients(t, issuingRestConfig)

	otherRestConfig := util.RestConfigWithUserAgent(restConfig, "other-status-writer")
	otherFieldManager := util.PrefixFromUserAgent(otherRestConfig.UserAgent)
	_, _, otherCMClient, _, _ := framework.NewClients(t, otherRestConfig)

	t.Run("omit clears scalars owned by applying manager", func(t *testing.T) {
		const (
			namespace = "test-status-scalar-apply-omit"
			name      = "omit-clears-owned-scalars"
		)

		t.Log("creating test Namespace")
		_, err := kubeClient.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespace},
		}, metav1.CreateOptions{})
		require.NoError(t, err)

		createEmptyCertificate(t, issuingCMClient, namespace, name)

		attempts := 2
		now := metav1.Now()
		t.Log("ApplyStatus sets scalar failure fields")
		applyCertificateStatus(t, issuingCMClient, issuingFieldManager, namespace, name, cmapi.CertificateStatus{
			FailedIssuanceAttempts: &attempts,
			LastFailureTime:        &now,
			Revision:               new(1),
		})

		crt, err := issuingCMClient.CertmanagerV1().Certificates(namespace).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		require.NotNil(t, crt.Status.FailedIssuanceAttempts)
		assert.Equal(t, 2, *crt.Status.FailedIssuanceAttempts)
		require.NotNil(t, crt.Status.LastFailureTime)

		t.Log("ApplyStatus omits scalar failure fields")
		applyCertificateStatus(t, issuingCMClient, issuingFieldManager, namespace, name, cmapi.CertificateStatus{
			Revision: new(2),
		})

		crt, err = issuingCMClient.CertmanagerV1().Certificates(namespace).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Nil(t, crt.Status.FailedIssuanceAttempts)
		assert.Nil(t, crt.Status.LastFailureTime)
		require.NotNil(t, crt.Status.Revision)
		assert.Equal(t, 2, *crt.Status.Revision)
	})

	t.Run("omit does not clear scalars owned by another manager", func(t *testing.T) {
		const (
			namespace = "test-status-scalar-apply-coown"
			name      = "omit-keeps-foreign-owned-scalars"
		)

		t.Log("creating test Namespace")
		_, err := kubeClient.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespace},
		}, metav1.CreateOptions{})
		require.NoError(t, err)

		createEmptyCertificate(t, issuingCMClient, namespace, name)

		attempts := 2
		now := metav1.Now()
		t.Log("ApplyStatus sets scalar failure fields")
		applyCertificateStatus(t, issuingCMClient, issuingFieldManager, namespace, name, cmapi.CertificateStatus{
			FailedIssuanceAttempts: &attempts,
			LastFailureTime:        &now,
			Revision:               new(1),
		})

		otherAttempts := 3
		t.Log("second field manager ApplyStatus claims failedIssuanceAttempts")
		// A second Apply manager. Managers are keyed by operation too, so the
		// Update to Apply case is a separate subtest below.
		applyCertificateStatus(t, otherCMClient, otherFieldManager, namespace, name, cmapi.CertificateStatus{
			FailedIssuanceAttempts: &otherAttempts,
		})

		crt, err := issuingCMClient.CertmanagerV1().Certificates(namespace).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		require.NotNil(t, crt.Status.FailedIssuanceAttempts)
		assert.Equal(t, 3, *crt.Status.FailedIssuanceAttempts)
		require.NotNil(t, crt.Status.LastFailureTime)

		t.Log("original manager omits failedIssuanceAttempts")
		applyCertificateStatus(t, issuingCMClient, issuingFieldManager, namespace, name, cmapi.CertificateStatus{
			Revision: new(2),
		})

		crt, err = issuingCMClient.CertmanagerV1().Certificates(namespace).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		require.NotNil(t, crt.Status.FailedIssuanceAttempts)
		assert.Equal(t, 3, *crt.Status.FailedIssuanceAttempts)
		assert.Nil(t, crt.Status.LastFailureTime)
		require.NotNil(t, crt.Status.Revision)
		assert.Equal(t, 2, *crt.Status.Revision)
	})

	// Scalars written by UpdateStatus before the ServerSideApply gate was
	// enabled stay owned by an operation:Update entry, which an omitting
	// ApplyStatus does not prune. Ownership moves once Apply writes them.
	t.Run("omit does not clear scalars owned by an Update manager, until Apply claims them", func(t *testing.T) {
		const (
			namespace = "test-status-scalar-apply-update-owner"
			name      = "omit-keeps-update-owned-scalars"
		)

		t.Log("creating test Namespace")
		_, err := kubeClient.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespace},
		}, metav1.CreateOptions{})
		require.NoError(t, err)

		createEmptyCertificate(t, issuingCMClient, namespace, name)

		t.Log("UpdateStatus sets the scalar failure fields, as the pre-gate code path did")
		crt, err := issuingCMClient.CertmanagerV1().Certificates(namespace).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		attempts := 2
		now := metav1.Now()
		crt.Status.FailedIssuanceAttempts = &attempts
		crt.Status.LastFailureTime = &now
		crt.Status.Revision = new(1)
		_, err = issuingCMClient.CertmanagerV1().Certificates(namespace).UpdateStatus(t.Context(), crt, metav1.UpdateOptions{})
		require.NoError(t, err)

		t.Log("ApplyStatus omitting the scalar failure fields does not clear them")
		applyCertificateStatus(t, issuingCMClient, issuingFieldManager, namespace, name, cmapi.CertificateStatus{
			Revision: new(2),
		})

		crt, err = issuingCMClient.CertmanagerV1().Certificates(namespace).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		require.NotNil(t, crt.Status.FailedIssuanceAttempts, "an Update-owned scalar must survive an omitting Apply")
		assert.Equal(t, 2, *crt.Status.FailedIssuanceAttempts)
		require.NotNil(t, crt.Status.LastFailureTime)

		t.Log("ApplyStatus including the scalar failure fields takes ownership of them")
		nextAttempts := 3
		// Distinct timestamp: an apply writing a field the value it already
		// holds does not take ownership, so a same-second metav1.Now() would
		// not exercise the transfer.
		nextNow := metav1.NewTime(now.Add(time.Hour))
		applyCertificateStatus(t, issuingCMClient, issuingFieldManager, namespace, name, cmapi.CertificateStatus{
			FailedIssuanceAttempts: &nextAttempts,
			LastFailureTime:        &nextNow,
			Revision:               new(2),
		})

		t.Log("a later omitting ApplyStatus now clears them")
		applyCertificateStatus(t, issuingCMClient, issuingFieldManager, namespace, name, cmapi.CertificateStatus{
			Revision: new(3),
		})

		crt, err = issuingCMClient.CertmanagerV1().Certificates(namespace).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Nil(t, crt.Status.FailedIssuanceAttempts, "the stale state must self-heal once Apply has claimed the field")
		assert.Nil(t, crt.Status.LastFailureTime)
		require.NotNil(t, crt.Status.Revision)
		assert.Equal(t, 3, *crt.Status.Revision)
	})
}

func createEmptyCertificate(t *testing.T, cmClient cmclient.Interface, namespace, name string) {
	t.Helper()
	t.Log("creating empty Certificate")
	_, err := cmClient.CertmanagerV1().Certificates(namespace).Create(t.Context(), &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: cmapi.CertificateSpec{
			CommonName: "test",
			SecretName: "test",
			IssuerRef:  cmmeta.IssuerReference{Name: "test"},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
}

// applyCertificateStatus calls the same ApplyStatus the controllers call.
func applyCertificateStatus(t *testing.T, cmClient cmclient.Interface, fieldManager, namespace, name string, status cmapi.CertificateStatus) {
	t.Helper()
	require.NoError(t, internalcertificates.ApplyStatus(t.Context(), cmClient, fieldManager, &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status:     status,
	}))
}
