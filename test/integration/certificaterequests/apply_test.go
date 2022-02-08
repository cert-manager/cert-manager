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

package certificaterequests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"

	internalcertificaterequests "github.com/cert-manager/cert-manager/internal/controller/certificaterequests"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/integration/framework"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
)

// Test_Apply ensures that the CertificateRequest Apply helpers can set both
// the ObjectMeta and Status objects respectively.
func Test_Apply(t *testing.T) {
	const (
		namespace = "test-apply"
		name      = "test-apply"
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	restConfig, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	kubeClient, _, cmClient, _ := framework.NewClients(t, restConfig)

	t.Log("creating test Namespace")
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err := kubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	bundle := testcrypto.MustCreateCryptoBundle(t, &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: cmapi.CertificateSpec{
			CommonName: "test-bundle-1",
			IssuerRef:  cmmeta.ObjectReference{Name: "test-bundle-1"},
		}},
		&fakeclock.FakeClock{},
	)
	req := bundle.CertificateRequest
	req.OwnerReferences = nil
	req.Name = name
	req.Labels = nil
	req.Annotations = nil

	t.Log("creating CertificateRequest")
	_, err = cmClient.CertmanagerV1().CertificateRequests(namespace).Create(ctx, req, metav1.CreateOptions{FieldManager: "cert-manager-test"})
	assert.NoError(t, err)

	t.Log("ensuring apply will can set annotations and labels")
	req, err = internalcertificaterequests.Apply(ctx, cmClient, "cert-manager-test", &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: name,
			Annotations: map[string]string{"test-1": "abc", "test-2": "def"},
			Labels:      map[string]string{"123": "456", "789": "abc"},
		},
		Spec: req.Spec,
	})
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"test-1": "abc", "test-2": "def"}, req.Annotations, "annotations")
	assert.Equal(t, map[string]string{"123": "456", "789": "abc"}, req.Labels, "labels")

	t.Log("ensuring apply will can status")
	assert.NoError(t,
		internalcertificaterequests.ApplyStatus(ctx, cmClient, "cert-manager-test", &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Status: cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{{Type: cmapi.CertificateRequestConditionType("Random"), Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"}},
			},
		}),
	)
	req, err = cmClient.CertmanagerV1().CertificateRequests(namespace).Get(ctx, name, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, []cmapi.CertificateRequestCondition{{Type: cmapi.CertificateRequestConditionType("Random"), Status: cmmeta.ConditionTrue, Reason: "reason", Message: "message"}}, req.Status.Conditions)
}
