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
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/test/integration/framework"
)

// Test_ConditionsListType ensures that the Certificate's Conditions API field
// has been labelled as a list map. This is so that district field managers are
// able to add and modify different Conditions without disrupting each others
// entries. Conditions are keyed by `Type`.
func Test_ConditionsListType(t *testing.T) {
	const (
		namespace = "test-condition-list-type"
		name      = "test-condition-list-type"
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	restConfig, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build clients with different field managers.
	aliceRestConfig := util.RestConfigWithUserAgent(restConfig, "alice")
	aliceFieldManager := util.PrefixFromUserAgent(aliceRestConfig.UserAgent)
	aliceKubeClient, _, aliceCMClient, _ := framework.NewClients(t, aliceRestConfig)

	bobRestConfig := util.RestConfigWithUserAgent(restConfig, "bob")
	bobFieldManager := util.PrefixFromUserAgent(bobRestConfig.UserAgent)
	_, _, bobCMClient, _ := framework.NewClients(t, bobRestConfig)

	t.Log("creating test Namespace")
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := aliceKubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	t.Log("creating empty Certificate")
	crt := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: cmapi.CertificateSpec{
			CommonName: "test", SecretName: "test", IssuerRef: cmmeta.ObjectReference{Name: "test"},
		},
	}
	_, err = aliceCMClient.CertmanagerV1().Certificates(namespace).Create(ctx, crt, metav1.CreateOptions{})
	assert.NoError(t, err)

	t.Log("ensuring alice can set Ready condition")
	crt = &cmapi.Certificate{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.CertificateKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.CertificateStatus{
			Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"}},
		},
	}
	crtData, err := json.Marshal(crt)
	assert.NoError(t, err)
	_, err = aliceCMClient.CertmanagerV1().Certificates(namespace).Patch(
		ctx, name, apitypes.ApplyPatchType, crtData,
		metav1.PatchOptions{Force: pointer.Bool(true), FieldManager: aliceFieldManager}, "status",
	)
	assert.NoError(t, err)

	t.Log("ensuring bob can set a district issuing condition, without changing the ready condition")
	crt = &cmapi.Certificate{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.CertificateKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.CertificateStatus{
			Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"}},
		},
	}
	crtData, err = json.Marshal(crt)
	assert.NoError(t, err)
	_, err = bobCMClient.CertmanagerV1().Certificates(namespace).Patch(
		ctx, name, apitypes.ApplyPatchType, crtData,
		metav1.PatchOptions{Force: pointer.Bool(true), FieldManager: bobFieldManager}, "status",
	)
	assert.NoError(t, err)

	crt, err = bobCMClient.CertmanagerV1().Certificates(namespace).Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.CertificateCondition{
		{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"},
		{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"},
	}, crt.Status.Conditions, "conditions did not match the expected 2 distinct condition types")

	t.Log("alice should override an existing condition by another manager, and can delete an existing owned condition type through omission")
	crt = &cmapi.Certificate{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.CertificateKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.CertificateStatus{
			Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse, Reason: "another-reason", Message: "another-message"}},
		},
	}
	crtData, err = json.Marshal(crt)
	assert.NoError(t, err)
	_, err = aliceCMClient.CertmanagerV1().Certificates(namespace).Patch(
		ctx, name, apitypes.ApplyPatchType, crtData,
		metav1.PatchOptions{Force: pointer.Bool(true), FieldManager: aliceFieldManager}, "status",
	)
	assert.NoError(t, err)

	crt, err = aliceCMClient.CertmanagerV1().Certificates(namespace).Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.CertificateCondition{
		{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse, Reason: "another-reason", Message: "another-message"},
	}, crt.Status.Conditions, "conditions did not match expected deleted ready condition, and overwritten issuing condition")

	t.Log("bob can re-add a Ready condition and not change Issuing condition")
	crt = &cmapi.Certificate{
		TypeMeta:   metav1.TypeMeta{Kind: cmapi.CertificateKind, APIVersion: cmapi.SchemeGroupVersion.Identifier()},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.CertificateStatus{
			Conditions: []cmapi.CertificateCondition{{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionFalse, Reason: "reason", Message: "message"}},
		},
	}
	crtData, err = json.Marshal(crt)
	assert.NoError(t, err)
	_, err = bobCMClient.CertmanagerV1().Certificates(namespace).Patch(
		ctx, name, apitypes.ApplyPatchType, crtData,
		metav1.PatchOptions{Force: pointer.Bool(true), FieldManager: bobFieldManager}, "status",
	)
	assert.NoError(t, err)

	crt, err = bobCMClient.CertmanagerV1().Certificates(namespace).Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.CertificateCondition{
		{Type: cmapi.CertificateConditionIssuing, Status: cmmeta.ConditionFalse, Reason: "another-reason", Message: "another-message"},
		{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionFalse, Reason: "reason", Message: "message"},
	}, crt.Status.Conditions, "expected bob to be able to add a distinct ready condition after no longer owning the issuing condition")
}
