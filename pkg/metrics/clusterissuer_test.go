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

package metrics

import (
	"strings"
	"testing"

	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/clock"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const cissReadyMetadata = `
	# HELP certmanager_clusterissuer_ready_status The ready status of the ClusterIssuer.
	# TYPE certmanager_clusterissuer_ready_status gauge
`

func TestClusterIssuerMetrics(t *testing.T) {
	type testT struct {
		ciss          *cmapi.ClusterIssuer
		expectedReady string
	}
	tests := map[string]testT{
		"clusterissuer with ready status True": {
			ciss: gen.ClusterIssuer("test-clusterissuer",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmmeta.ConditionTrue,
				}),
			),
			expectedReady: `
		certmanager_clusterissuer_ready_status{condition="True",name="test-clusterissuer"} 1
		certmanager_clusterissuer_ready_status{condition="False",name="test-clusterissuer"} 0
		certmanager_clusterissuer_ready_status{condition="Unknown",name="test-clusterissuer"} 0
`,
		},
		"clusterissuer with ready status False": {
			ciss: gen.ClusterIssuer("test-clusterissuer",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmmeta.ConditionFalse,
				}),
			),
			expectedReady: `
		certmanager_clusterissuer_ready_status{condition="True",name="test-clusterissuer"} 0
		certmanager_clusterissuer_ready_status{condition="False",name="test-clusterissuer"} 1
		certmanager_clusterissuer_ready_status{condition="Unknown",name="test-clusterissuer"} 0
`,
		},
		"clusterissuer with ready status Unknown": {
			ciss: gen.ClusterIssuer("test-clusterissuer",
				gen.AddIssuerCondition(cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmmeta.ConditionUnknown,
				}),
			),
			expectedReady: `
		certmanager_clusterissuer_ready_status{condition="True",name="test-clusterissuer"} 0
		certmanager_clusterissuer_ready_status{condition="False",name="test-clusterissuer"} 0
		certmanager_clusterissuer_ready_status{condition="Unknown",name="test-clusterissuer"} 1
`,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			m := New(testr.New(t), clock.RealClock{})

			fakeClient := fake.NewClientset()
			factory := externalversions.NewSharedInformerFactory(fakeClient, 0)
			cissInformer := factory.Certmanager().V1().ClusterIssuers()

			err := cissInformer.Informer().GetIndexer().Add(test.ciss)
			assert.NoError(t, err)

			m.SetupClusterIssuerCollector(cissInformer.Lister())

			if err := testutil.CollectAndCompare(m.clusterIssuerCollector,
				strings.NewReader(cissReadyMetadata+test.expectedReady),
				"certmanager_clusterissuer_ready_status",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			err = cissInformer.Informer().GetIndexer().Delete(test.ciss)
			assert.NoError(t, err)
		})
	}
}
