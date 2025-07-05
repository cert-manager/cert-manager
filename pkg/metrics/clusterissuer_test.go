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

	logtesting "github.com/go-logr/logr/testing"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/clock"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const cissReadyMetadata = `
	# HELP certmanager_clusterissuer_ready_status The ready status of the clusterissuer
	# TYPE certmanager_clusterissuer_ready_status gauge
`

func TestClusterIssuerMetrics(t *testing.T) {
	type testT struct {
		ciss          *cmapi.ClusterIssuer
		expectedReady string
	}
	tests := map[string]testT{
		"clusterissuer with ready status": {
			ciss: gen.ClusterIssuer("test-clusterissuer"),
			expectedReady: `
		certmanager_clusterissuer_ready_status{condition="False",name="test-clusterissuer"} 0
		certmanager_clusterissuer_ready_status{condition="True",name="test-clusterissuer"} 0
		certmanager_clusterissuer_ready_status{condition="Unknown",name="test-clusterissuer"} 1
`,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			m := New(logtesting.NewTestLogger(t), clock.RealClock{})
			m.UpdateClusterIssuer(test.ciss)

			if err := testutil.CollectAndCompare(m.clusterIssuerReadyStatus,
				strings.NewReader(cissReadyMetadata+test.expectedReady),
				"certmanager_clusterissuer_ready_status",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			m.RemoveClusterIssuer(types.NamespacedName{
				Name: "test-clusterissuer",
			})

			if testutil.CollectAndCount(m.clusterIssuerReadyStatus, "certmanager_clusterissuer_ready_status") != 0 {
				t.Errorf("unexpected collecting result")
			}
		})
	}
}
