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

package issuers

import (
	"testing"
	"time"

	internalissuers "github.com/cert-manager/cert-manager/internal/controller/issuers"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
)

func Test_ConditionsListType_Issuers(t *testing.T) {
	const (
		namespace = "test-condition-list-type"
		name      = "test-condition-list-type"
	)

	// Rounding "now" to the nearest second to avoid failing tests.
	// When using SSA, nanos/millis are removed from metav1.Time fields.
	nowTime := time.Now().Round(time.Second)
	nowMetaTime := metav1.NewTime(nowTime)

	restConfig, stopFn := framework.RunControlPlane(t)
	t.Cleanup(stopFn)

	// Build clients with different field managers.
	aliceRestConfig := util.RestConfigWithUserAgent(restConfig, "alice")
	aliceFieldManager := util.PrefixFromUserAgent(aliceRestConfig.UserAgent)
	aliceKubeClient, _, aliceCMClient, _, _ := framework.NewClients(t, aliceRestConfig)

	bobRestConfig := util.RestConfigWithUserAgent(restConfig, "bob")
	bobFieldManager := util.PrefixFromUserAgent(bobRestConfig.UserAgent)
	_, _, bobCMClient, _, _ := framework.NewClients(t, bobRestConfig)

	t.Log("creating test Namespace")
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := aliceKubeClient.CoreV1().Namespaces().Create(t.Context(), ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	t.Log("creating Issuer")
	_, err = aliceCMClient.CertmanagerV1().Issuers(namespace).Create(t.Context(), &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{
			SelfSigned: new(cmapi.SelfSignedIssuer),
		}},
	}, metav1.CreateOptions{})
	assert.NoError(t, err)

	t.Log("ensuring alice can set Ready condition")
	assert.NoError(t, internalissuers.ApplyIssuerStatus(t.Context(), aliceCMClient, aliceFieldManager, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime}},
		},
	}))

	t.Log("ensuring bob can set a district random condition, without changing the ready condition")
	assert.NoError(t, internalissuers.ApplyIssuerStatus(t.Context(), bobCMClient, bobFieldManager, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime}},
		},
	}))

	issuer, err := bobCMClient.CertmanagerV1().Issuers(namespace).Get(t.Context(), name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime},
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime},
	}, issuer.Status.Conditions, "conditions did not match the expected 2 distinct condition types")

	t.Log("alice should override an existing condition by another manager, and can delete an existing owned condition type through omission")
	assert.NoError(t, internalissuers.ApplyIssuerStatus(t.Context(), aliceCMClient, aliceFieldManager, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "AnotherReason", Message: "another-message", LastTransitionTime: nowMetaTime}},
		},
	}))

	issuer, err = aliceCMClient.CertmanagerV1().Issuers(namespace).Get(t.Context(), name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "AnotherReason", Message: "another-message", LastTransitionTime: nowMetaTime},
	}, issuer.Status.Conditions, "conditions did not match expected deleted ready condition, and overwritten random condition")

	t.Log("bob can re-add a Ready condition and not change Random condition")
	assert.NoError(t, internalissuers.ApplyIssuerStatus(t.Context(), bobCMClient, bobFieldManager, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionFalse, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime}},
		},
	}))

	issuer, err = bobCMClient.CertmanagerV1().Issuers(namespace).Get(t.Context(), name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "AnotherReason", Message: "another-message", LastTransitionTime: nowMetaTime},
		{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionFalse, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime},
	}, issuer.Status.Conditions, "expected bob to be able to add a distinct ready condition after no longer owning the random condition")
}

func Test_ConditionsListType_ClusterIssuers(t *testing.T) {
	const (
		name = "test-condition-list-type"
	)

	// Rounding "now" to the nearest second to avoid failing tests.
	// When using SSA, nanos/millis are removed from metav1.Time fields.
	nowTime := time.Now().Round(time.Second)
	nowMetaTime := metav1.NewTime(nowTime)

	restConfig, stopFn := framework.RunControlPlane(t)
	t.Cleanup(stopFn)

	// Build clients with different field managers.
	aliceRestConfig := util.RestConfigWithUserAgent(restConfig, "alice")
	aliceFieldManager := util.PrefixFromUserAgent(aliceRestConfig.UserAgent)
	_, _, aliceCMClient, _, _ := framework.NewClients(t, aliceRestConfig)

	bobRestConfig := util.RestConfigWithUserAgent(restConfig, "bob")
	bobFieldManager := util.PrefixFromUserAgent(bobRestConfig.UserAgent)
	_, _, bobCMClient, _, _ := framework.NewClients(t, bobRestConfig)

	t.Log("creating ClusterIssuer")
	_, err := aliceCMClient.CertmanagerV1().ClusterIssuers().Create(t.Context(), &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{
			SelfSigned: new(cmapi.SelfSignedIssuer),
		}},
	}, metav1.CreateOptions{})
	assert.NoError(t, err)

	t.Log("ensuring alice can set Ready condition")
	assert.NoError(t, internalissuers.ApplyClusterIssuerStatus(t.Context(), aliceCMClient, aliceFieldManager, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime}},
		},
	}))

	t.Log("ensuring bob can set a district random condition, without changing the ready condition")
	assert.NoError(t, internalissuers.ApplyClusterIssuerStatus(t.Context(), bobCMClient, bobFieldManager, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime}},
		},
	}))

	issuer, err := bobCMClient.CertmanagerV1().ClusterIssuers().Get(t.Context(), name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime},
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime},
	}, issuer.Status.Conditions, "conditions did not match the expected 2 distinct condition types")

	t.Log("alice should override an existing condition by another manager, and can delete an existing owned condition type through omission")
	assert.NoError(t, internalissuers.ApplyClusterIssuerStatus(t.Context(), aliceCMClient, aliceFieldManager, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "AnotherReason", Message: "another-message", LastTransitionTime: nowMetaTime}},
		},
	}))

	issuer, err = aliceCMClient.CertmanagerV1().ClusterIssuers().Get(t.Context(), name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "AnotherReason", Message: "another-message", LastTransitionTime: nowMetaTime},
	}, issuer.Status.Conditions, "conditions did not match expected deleted ready condition, and overwritten random condition")

	t.Log("bob can re-add a Ready condition and not change Random condition")
	assert.NoError(t, internalissuers.ApplyClusterIssuerStatus(t.Context(), bobCMClient, bobFieldManager, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionFalse, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime}},
		},
	}))

	issuer, err = bobCMClient.CertmanagerV1().ClusterIssuers().Get(t.Context(), name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "AnotherReason", Message: "another-message", LastTransitionTime: nowMetaTime},
		{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionFalse, Reason: "reason", Message: "message", LastTransitionTime: nowMetaTime},
	}, issuer.Status.Conditions, "expected bob to be able to add a distinct ready condition after no longer owning the random condition")
}
