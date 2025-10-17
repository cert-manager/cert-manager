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
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

const issReadyMetadata = `
	# HELP certmanager_issuer_ready_status The ready status of the Issuer.
	# TYPE certmanager_issuer_ready_status gauge
`

func TestIssuerMetrics(t *testing.T) {
	type testT struct {
		iss           *cmapi.Issuer
		expectedReady string
	}
	tests := map[string]testT{
		"issuer with ready status": {
			iss: gen.Issuer("test-issuer",
				gen.SetIssuerNamespace("test-ns"),
			),
			expectedReady: `
		certmanager_issuer_ready_status{condition="False",name="test-issuer",namespace="test-ns"} 0
		certmanager_issuer_ready_status{condition="True",name="test-issuer",namespace="test-ns"} 0
		certmanager_issuer_ready_status{condition="Unknown",name="test-issuer",namespace="test-ns"} 1
`,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			m := New(testr.New(t), clock.RealClock{})

			fakeClient := fake.NewClientset()
			factory := externalversions.NewSharedInformerFactory(fakeClient, 0)
			issInformer := factory.Certmanager().V1().Issuers()

			err := issInformer.Informer().GetIndexer().Add(test.iss)
			assert.NoError(t, err)

			m.SetupIssuerCollector(issInformer.Lister())

			if err := testutil.CollectAndCompare(m.issuerCollector,
				strings.NewReader(issReadyMetadata+test.expectedReady),
				"certmanager_issuer_ready_status",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}

			err = issInformer.Informer().GetIndexer().Delete(test.iss)
			assert.NoError(t, err)
		})
	}
}
