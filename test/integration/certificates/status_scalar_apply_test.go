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
	"encoding/json"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"

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

func applyCertificateStatus(t *testing.T, cmClient cmclient.Interface, fieldManager, namespace, name string, status cmapi.CertificateStatus) {
	t.Helper()
	patch, err := json.Marshal(&cmapi.Certificate{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.CertificateKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status:     status,
	})
	require.NoError(t, err)
	_, err = cmClient.CertmanagerV1().Certificates(namespace).Patch(
		t.Context(), name, apitypes.ApplyPatchType, patch,
		metav1.PatchOptions{Force: new(true), FieldManager: fieldManager}, "status",
	)
	require.NoError(t, err)
}
