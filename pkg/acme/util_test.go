/*
Copyright 2026 The cert-manager Authors.

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
	"testing"

	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestARIEnabledForIssuer(t *testing.T) {
	tests := map[string]struct {
		featureEnabled bool
		issuer         cmapi.GenericIssuer
		want           bool
	}{
		"feature gate disabled returns false even when issuer opts in": {
			featureEnabled: false,
			issuer: gen.Issuer("test", gen.SetIssuerACME(cmacme.ACMEIssuer{
				RenewalInformationSource: cmacme.ACMERenewalInformationSourceARI,
			})),
			want: false,
		},
		"nil issuer returns false": {
			featureEnabled: true,
			issuer:         nil,
			want:           false,
		},
		"non-ACME issuer returns false": {
			featureEnabled: true,
			issuer:         gen.Issuer("test", gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{})),
			want:           false,
		},
		"empty renewalInformationSource defaults to enabled": {
			featureEnabled: true,
			issuer:         gen.Issuer("test", gen.SetIssuerACME(cmacme.ACMEIssuer{})),
			want:           true,
		},
		"explicit ARI is enabled": {
			featureEnabled: true,
			issuer: gen.Issuer("test", gen.SetIssuerACME(cmacme.ACMEIssuer{
				RenewalInformationSource: cmacme.ACMERenewalInformationSourceARI,
			})),
			want: true,
		},
		"explicit None is disabled": {
			featureEnabled: true,
			issuer: gen.Issuer("test", gen.SetIssuerACME(cmacme.ACMEIssuer{
				RenewalInformationSource: cmacme.ACMERenewalInformationSourceNone,
			})),
			want: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(
				t, utilfeature.DefaultFeatureGate, feature.ACMEUseARI, test.featureEnabled)

			if got := ARIEnabledForIssuer(test.issuer); got != test.want {
				t.Errorf("ARIEnabledForIssuer() = %v, want %v", got, test.want)
			}
		})
	}
}
