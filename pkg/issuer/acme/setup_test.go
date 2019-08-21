/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package acme

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/feature"
	utilfeature "github.com/jetstack/cert-manager/pkg/util/feature"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

type testT struct {
	issuer      *cmapi.Issuer
	builder     *testpkg.Builder
	expectedErr bool
}

func TestDisableOldConfigFeatureFlagDisabled(t *testing.T) {
	baseIssuer := gen.Issuer("testissuer",
		gen.SetIssuerACME(cmapi.ACMEIssuer{}),
	)
	issuerOldHTTP01Config := gen.IssuerFrom(baseIssuer,
		gen.SetIssuerACME(cmapi.ACMEIssuer{
			HTTP01: &cmapi.ACMEIssuerHTTP01Config{},
		}),
	)
	issuerOldDNS01Config := gen.IssuerFrom(baseIssuer,
		gen.SetIssuerACME(cmapi.ACMEIssuer{
			DNS01: &cmapi.ACMEIssuerDNS01Config{},
		}),
	)

	tests := map[string]testT{
		"log an event and exit if an issuer that specifies the old HTTP01 config format is processed": {
			issuer: issuerOldHTTP01Config,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					issuerOldHTTP01Config,
				},
				ExpectedEvents: []string{
					`Warning DeprecatedField Deprecated spec.acme.{http01,dns01} field specified and deprecated field feature gate is enabled.`,
				},
			},
		},
		"log an event and exit if an issuer that specifies the old DNS01 config format is processed": {
			issuer: issuerOldDNS01Config,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					issuerOldDNS01Config,
				},
				ExpectedEvents: []string{
					`Warning DeprecatedField Deprecated spec.acme.{http01,dns01} field specified and deprecated field feature gate is enabled.`,
				},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.DisableDeprecatedACMECertificates, true)()
			runSetupTest(t, test)
		})
	}
}

func runSetupTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	c, err := New(test.builder.Context, test.issuer)
	if err != nil {
		t.Fatalf("error building ACME fixture: %v", err)
	}
	test.builder.Start()

	err = c.Setup(context.Background())
	if err != nil && !test.expectedErr {
		t.Errorf("expected to not get an error, but got: %v", err)
	}
	if err == nil && test.expectedErr {
		t.Errorf("expected to get an error but did not get one")
	}

	test.builder.CheckAndFinish(err)
}
