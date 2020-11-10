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

package venafi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kr/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

// TestControllerIntegration is an integration test to demonstrate that the
// Venafi ClusterIssuer controller can process ClusterIssuers when using all its
// default injected dependencies.
func TestControllerIntegration(t *testing.T) {
	builder := &testpkg.Builder{
		T: t,
		CertManagerObjects: []runtime.Object{
			gen.ClusterIssuer(
				"clusterissuer-1",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{
					Zone: `foo\bar`,
					TPP: &cmapi.VenafiTPP{
						URL: "https://tpp.example.com/vedsdk/",
						CredentialsRef: cmmeta.LocalObjectReference{
							Name: "secret-1",
						},
					},
				}),
			),
		},
		KubeObjects: []runtime.Object{
			gen.Secret(
				"secret-1",
				gen.SetSecretNamespace("ns1"),
				gen.SetSecretData(map[string][]byte{
					"access-token": []byte("fake-access-token"),
					"expires":      []byte(fmt.Sprintf("%d", time.Now().Add(time.Hour*24).Unix())),
				}),
			),
		},
	}

	builder.Init()
	defer builder.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = logf.NewContext(ctx, logf.Log, "Test")
	controllerContext := &controllerpkg.Context{
		IssuerOptions: controllerpkg.IssuerOptions{
			ClusterResourceNamespace: "ns1",
		},
		RootContext:               ctx,
		Client:                    builder.FakeKubeClient(),
		CMClient:                  builder.FakeCMClient(),
		KubeSharedInformerFactory: builder.FakeKubeInformerFactory(),
		SharedInformerFactory:     builder.FakeCMInformerFactory(),
	}

	c := &controller{}

	queue, synced, err := c.Register(controllerContext)
	require.NoError(t, err)

	builder.Start()

	assert.Equal(t, queue.Len(), 1)
	assert.Len(t, synced, 2)

	err = c.ProcessItem(ctx, "clusterissuer-1")
	assert.Error(t, err)

	issuer, err := builder.FakeCMClient().CertmanagerV1().ClusterIssuers().Get(ctx, "clusterissuer-1", metav1.GetOptions{})
	assert.NoError(t, err)

	assert.Truef(t, apiutil.IssuerHasCondition(issuer, cmapi.IssuerCondition{
		Type:   cmapi.IssuerConditionReady,
		Status: cmmeta.ConditionFalse,
	}), "unexpected condition: %#v", issuer)
	t.Log(pretty.Sprint(issuer))
}
