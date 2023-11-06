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

package challenges

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	internalchallenges "github.com/cert-manager/cert-manager/internal/controller/challenges"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// Test_Apply ensures that the Challenge Apply helpers can set both the
// ObjectMeta/Spec and Status objects respectively.
func Test_Apply(t *testing.T) {
	const (
		namespace = "test-apply"
		name      = "test-apply"
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	restConfig, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	kubeClient, _, cmClient, _, _ := framework.NewClients(t, restConfig)

	t.Log("creating test Namespace")
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	ch := &cmacme.Challenge{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: cmacme.ChallengeSpec{
			URL: "http://example.com", AuthorizationURL: "http://example.com/auth",
			DNSName: "example.com", Wildcard: true,
			Type: cmacme.ACMEChallengeTypeDNS01, Token: "1234", Key: "5678",
			Solver: cmacme.ACMEChallengeSolver{},
			IssuerRef: cmmeta.ObjectReference{
				Name:  "issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			},
		},
	}

	t.Log("creating Challenge")
	_, err = cmClient.AcmeV1().Challenges(namespace).Create(ctx, ch, metav1.CreateOptions{FieldManager: "cert-manager-test"})
	assert.NoError(t, err)

	t.Log("ensuring apply will can set annotations and labels")
	_, err = internalchallenges.Apply(ctx, cmClient, "cert-manager-test", &cmacme.Challenge{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: name,
			Annotations: map[string]string{"test-1": "abc", "test-2": "def"},
			Labels:      map[string]string{"123": "456", "789": "abc"},
		},
		Spec: ch.Spec,
	})
	assert.NoError(t, err)
	ch, err = cmClient.AcmeV1().Challenges(namespace).Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"test-1": "abc", "test-2": "def"}, ch.Annotations, "annotations")
	assert.Equal(t, map[string]string{"123": "456", "789": "abc"}, ch.Labels, "labels")

	t.Log("ensuring apply can change status")
	_, err = internalchallenges.ApplyStatus(ctx, cmClient, "cert-manager-test", &cmacme.Challenge{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: cmacme.ChallengeStatus{
			Processing: true,
			Presented:  true,
			Reason:     "this is a reason",
			State:      cmacme.State("errored"),
		},
	})
	assert.NoError(t, err)
	ch, err = cmClient.AcmeV1().Challenges(namespace).Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, cmacme.ChallengeStatus{
		Processing: true,
		Presented:  true,
		Reason:     "this is a reason",
		State:      cmacme.State("errored"),
	}, ch.Status)
}
