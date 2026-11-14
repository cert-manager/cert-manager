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

package validation

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmacme "github.com/cert-manager/cert-manager/internal/apis/acme"
	cmapi "github.com/cert-manager/cert-manager/internal/apis/certmanager"
)

func TestValidateClusterIssuer(t *testing.T) {
	scenarios := map[string]struct {
		cfg       *cmapi.ClusterIssuer
		a         *admissionv1.AdmissionRequest
		expectedE []*field.Error
		expectedW []string
	}{}

	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			gotE, gotW := ValidateClusterIssuer(s.a, s.cfg)
			field.ErrorMatcher{}.ByType().ByField().ByDetailExact().Test(t, s.expectedE, gotE)
			assert.Equal(t, s.expectedW, gotW)
		})
	}
}

func TestUpdateValidateClusterIssuer(t *testing.T) {
	baseIssuerConfig := cmapi.IssuerSpec{
		SelfSigned: &cmapi.SelfSignedIssuer{},
	}
	baseIssuer := cmapi.ClusterIssuer{
		Spec: baseIssuerConfig,
	}

	rfc2136ClusterIssuer := func(algorithm string) *cmapi.ClusterIssuer {
		return &cmapi.ClusterIssuer{
			Spec: cmapi.IssuerSpec{
				IssuerConfig: cmapi.IssuerConfig{
					ACME: &cmacme.ACMEIssuer{
						Email:      "valid-email",
						Server:     "valid-server",
						PrivateKey: validSecretKeyRef,
						Solvers: []cmacme.ACMEChallengeSolver{
							{
								DNS01: &cmacme.ACMEChallengeSolverDNS01{
									RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
										Nameserver:    "127.0.0.1",
										TSIGAlgorithm: algorithm,
									},
								},
							},
						},
					},
				},
			},
		}
	}

	scenarios := map[string]struct {
		old       *cmapi.ClusterIssuer
		iss       *cmapi.ClusterIssuer
		a         *admissionv1.AdmissionRequest
		expectedE []*field.Error
		expectedW []string
	}{
		"unchanged deprecated solver does not warn": {
			old: rfc2136ClusterIssuer("HMACMD5"),
			iss: rfc2136ClusterIssuer("HMACMD5"),
		},
		"changed deprecated solver warns": {
			old: rfc2136ClusterIssuer("HMACSHA256"),
			iss: rfc2136ClusterIssuer("HMACMD5"),
			expectedW: []string{
				fmt.Sprintf(deprecatedRFC2136TSIGAlgorithm, "spec.acme.solvers[0].dns01.rfc2136.tsigAlgorithm", "HMACMD5"),
			},
		},
	}

	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			old := &baseIssuer
			if s.old != nil {
				old = s.old
			}
			gotE, gotW := ValidateUpdateClusterIssuer(s.a, old, s.iss)
			field.ErrorMatcher{}.ByType().ByField().ByDetailExact().Test(t, s.expectedE, gotE)
			assert.Equal(t, s.expectedW, gotW)
		})
	}
}
