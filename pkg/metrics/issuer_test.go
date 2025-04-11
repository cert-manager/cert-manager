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

const issReadyMetadata = `
		# HELP certmanager_issuer_ready_status The ready status of the issuer
		# TYPE certmanager_issuer_ready_status gauge
`

func TestIssuerMetrics(t *testing.T) {
	type testT struct {
		ciss          *cmapi.Issuer
		expectedReady string
	}
	tests := map[string]testT{
		"issuer with ready status": {
			ciss: gen.Issuer("test-issuer", gen.SetIssuerNamespace("default")),
			expectedReady: `
		certmanager_issuer_ready_status{condition="False",name="test-issuer",namespace="default"} 0
		certmanager_issuer_ready_status{condition="True",name="test-issuer",namespace="default"} 0
		certmanager_issuer_ready_status{condition="Unknown",name="test-issuer",namespace="default"} 1
`,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			m := New(logtesting.NewTestLogger(t), clock.RealClock{})
			m.UpdateIssuer(test.ciss)

			if err := testutil.CollectAndCompare(m.issuerReadyStatus,
				strings.NewReader(issReadyMetadata+test.expectedReady),
				"certmanager_issuer_ready_status",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			m.RemoveIssuer(types.NamespacedName{
				Name:      "test-issuer",
				Namespace: "default",
			})

			if testutil.CollectAndCount(m.issuerReadyStatus, "certmanager_issuer_ready_status") != 0 {
				t.Errorf("unexpected collecting result")
			}
		})
	}
}
