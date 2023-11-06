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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	internalissuers "github.com/cert-manager/cert-manager/internal/controller/issuers"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
)

func Test_ConditionsListType_Issuers(t *testing.T) {
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
	aliceKubeClient, _, aliceCMClient, _, _ := framework.NewClients(t, aliceRestConfig)

	bobRestConfig := util.RestConfigWithUserAgent(restConfig, "bob")
	bobFieldManager := util.PrefixFromUserAgent(bobRestConfig.UserAgent)
	_, _, bobCMClient, _, _ := framework.NewClients(t, bobRestConfig)

	t.Log("creating test Namespace")
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := aliceKubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	t.Log("creating Issuer")
	_, err = aliceCMClient.CertmanagerV1().Issuers(namespace).Create(ctx, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{
			SelfSigned: new(cmapi.SelfSignedIssuer),
		}},
	}, metav1.CreateOptions{})
	assert.NoError(t, err)

	t.Log("ensuring alice can set Ready condition")
	assert.NoError(t, internalissuers.ApplyIssuerStatus(ctx, aliceCMClient, aliceFieldManager, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"}},
		},
	}))

	t.Log("ensuring bob can set a district random condition, without changing the ready condition")
	assert.NoError(t, internalissuers.ApplyIssuerStatus(ctx, bobCMClient, bobFieldManager, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"}},
		},
	}))

	issuer, err := bobCMClient.CertmanagerV1().Issuers(namespace).Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"},
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"},
	}, issuer.Status.Conditions, "conditions did not match the expected 2 distinct condition types")

	t.Log("alice should override an existing condition by another manager, and can delete an existing owned condition type through omission")
	assert.NoError(t, internalissuers.ApplyIssuerStatus(ctx, aliceCMClient, aliceFieldManager, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "another-reason", Message: "another-message"}},
		},
	}))

	issuer, err = aliceCMClient.CertmanagerV1().Issuers(namespace).Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "another-reason", Message: "another-message"},
	}, issuer.Status.Conditions, "conditions did not match expected deleted ready condition, and overwritten random condition")

	t.Log("bob can re-add a Ready condition and not change Random condition")
	assert.NoError(t, internalissuers.ApplyIssuerStatus(ctx, bobCMClient, bobFieldManager, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionFalse, Reason: "reason", Message: "message"}},
		},
	}))

	issuer, err = bobCMClient.CertmanagerV1().Issuers(namespace).Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "another-reason", Message: "another-message"},
		{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionFalse, Reason: "reason", Message: "message"},
	}, issuer.Status.Conditions, "expected bob to be able to add a distinct ready condition after no longer owning the random condition")
}

func Test_ConditionsListType_ClusterIssuers(t *testing.T) {
	const (
		name = "test-condition-list-type"
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	restConfig, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build clients with different field managers.
	aliceRestConfig := util.RestConfigWithUserAgent(restConfig, "alice")
	aliceFieldManager := util.PrefixFromUserAgent(aliceRestConfig.UserAgent)
	_, _, aliceCMClient, _, _ := framework.NewClients(t, aliceRestConfig)

	bobRestConfig := util.RestConfigWithUserAgent(restConfig, "bob")
	bobFieldManager := util.PrefixFromUserAgent(bobRestConfig.UserAgent)
	_, _, bobCMClient, _, _ := framework.NewClients(t, bobRestConfig)

	t.Log("creating ClusterIssuer")
	_, err := aliceCMClient.CertmanagerV1().ClusterIssuers().Create(ctx, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{
			SelfSigned: new(cmapi.SelfSignedIssuer),
		}},
	}, metav1.CreateOptions{})
	assert.NoError(t, err)

	t.Log("ensuring alice can set Ready condition")
	assert.NoError(t, internalissuers.ApplyClusterIssuerStatus(ctx, aliceCMClient, aliceFieldManager, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"}},
		},
	}))

	t.Log("ensuring bob can set a district random condition, without changing the ready condition")
	assert.NoError(t, internalissuers.ApplyClusterIssuerStatus(ctx, bobCMClient, bobFieldManager, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"}},
		},
	}))

	issuer, err := bobCMClient.CertmanagerV1().ClusterIssuers().Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"},
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"},
	}, issuer.Status.Conditions, "conditions did not match the expected 2 distinct condition types")

	t.Log("alice should override an existing condition by another manager, and can delete an existing owned condition type through omission")
	assert.NoError(t, internalissuers.ApplyClusterIssuerStatus(ctx, aliceCMClient, aliceFieldManager, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "another-reason", Message: "another-message"}},
		},
	}))

	issuer, err = aliceCMClient.CertmanagerV1().ClusterIssuers().Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "another-reason", Message: "another-message"},
	}, issuer.Status.Conditions, "conditions did not match expected deleted ready condition, and overwritten random condition")

	t.Log("bob can re-add a Ready condition and not change Random condition")
	assert.NoError(t, internalissuers.ApplyClusterIssuerStatus(ctx, bobCMClient, bobFieldManager, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: cmapi.IssuerStatus{
			Conditions: []cmapi.IssuerCondition{{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionFalse, Reason: "reason", Message: "message"}},
		},
	}))

	issuer, err = bobCMClient.CertmanagerV1().ClusterIssuers().Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.IssuerCondition{
		{Type: cmapi.IssuerConditionType("Random"), Status: cmmeta.ConditionFalse, Reason: "another-reason", Message: "another-message"},
		{Type: cmapi.IssuerConditionReady, Status: cmmeta.ConditionFalse, Reason: "reason", Message: "message"},
	}, issuer.Status.Conditions, "expected bob to be able to add a distinct ready condition after no longer owning the random condition")
}
