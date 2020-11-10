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

package genericissuer

import (
	"context"
	"errors"
	"testing"

	"github.com/Venafi/vcert/v4/pkg/endpoint"
	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	venaficlient "github.com/jetstack/cert-manager/pkg/internal/venafi/client"
	venaficlientfake "github.com/jetstack/cert-manager/pkg/internal/venafi/client/fake"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestSync(t *testing.T) {
	type testCase struct {
		ctx                     context.Context
		venafiClientBuilder     venaficlient.Builder
		vc                      *venaficlientfake.Venafi
		issuer                  cmapi.GenericIssuer
		builder                 *testpkg.Builder
		expectRotateCredentials bool
		err                     error
	}

	tests := map[string]testCase{
		"success": {
			issuer: gen.Issuer("issuer-1", gen.SetIssuerNamespace("ns1")),
		},
		"failing client factory": {
			issuer: gen.Issuer("issuer-1", gen.SetIssuerNamespace("ns1")),
			venafiClientBuilder: func(_ context.Context, _ cmapi.GenericIssuer) (venaficlient.Interface, error) {
				return nil, errors.New("simulated venafi client builder error")
			},
			err: errClientBuilder,
		},
		"failing authentication": {
			issuer: gen.Issuer("issuer-1", gen.SetIssuerNamespace("ns1")),
			vc: &venaficlientfake.Venafi{
				AuthenticateFn: func() error { return errors.New("simulated authenticate error") },
			},
			err: errAuthenticate,
		},
		"failing readzoneconfiguration": {
			issuer: gen.Issuer("issuer-1", gen.SetIssuerNamespace("ns1")),
			vc: &venaficlientfake.Venafi{
				ReadZoneConfigurationFn: func() (*endpoint.ZoneConfiguration, error) {
					return nil, errors.New("simulated readzoneconfiguration error")
				},
			},
			err: errReadZoneConfiguration,
		},
		"rotate credentials if access-token expired": {
			issuer: gen.Issuer("issuer-1", gen.SetIssuerNamespace("ns1")),
			vc: &venaficlientfake.Venafi{
				AuthenticateFn: func() error { return venaficlient.ErrAccessTokenExpired },
			},
			expectRotateCredentials: true,
		},
		"rotate credentials if access-token missing": {
			issuer: gen.Issuer("issuer-1", gen.SetIssuerNamespace("ns1")),
			vc: &venaficlientfake.Venafi{
				AuthenticateFn: func() error { return venaficlient.ErrAccessTokenMissing },
			},
			expectRotateCredentials: true,
		},
		"rotate credentials error": {
			issuer: gen.Issuer("issuer-1", gen.SetIssuerNamespace("ns1")),
			vc: &venaficlientfake.Venafi{
				AuthenticateFn:      func() error { return venaficlient.ErrAccessTokenMissing },
				RotateCredentialsFn: func() error { return errors.New("simulated rotatecredentials error") },
			},
			err: errRotateCredentials,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			builder := tc.builder
			if builder == nil {
				builder = &testpkg.Builder{}
			}
			builder.T = t
			builder.Init()
			defer builder.Stop()

			ctx := tc.ctx
			if ctx == nil {
				ctx = context.TODO()
			}
			log := logrtesting.TestLogger{T: t}
			ctx = logf.NewContext(ctx, log)

			vc := tc.vc
			if vc == nil {
				vc = &venaficlientfake.Venafi{}
			}
			if vc.ReadZoneConfigurationFn == nil {
				vc.ReadZoneConfigurationFn = func() (*endpoint.ZoneConfiguration, error) {
					return &endpoint.ZoneConfiguration{}, nil
				}
			}
			if vc.AuthenticateFn == nil {
				vc.AuthenticateFn = func() error {
					return nil
				}
			}
			credentialsWereRotated := false
			if vc.RotateCredentialsFn == nil {
				vc.RotateCredentialsFn = func() error {
					credentialsWereRotated = true
					return nil
				}
			}
			venafiClientBuilder := tc.venafiClientBuilder
			if venafiClientBuilder == nil {
				venafiClientBuilder = func(_ context.Context, _ cmapi.GenericIssuer) (venaficlient.Interface, error) {
					return vc, nil
				}
			}
			s := &realSyncer{
				venafiClientBuilder: venafiClientBuilder,
			}

			builder.Start()
			err := s.Sync(ctx, tc.issuer)
			if tc.err == nil {
				assert.NoError(t, err)
				assertIssuerHasCondition(t, tc.issuer, cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmmeta.ConditionTrue,
				})
			} else {
				assertErrorIs(t, err, tc.err)
				assertIssuerHasCondition(t, tc.issuer, cmapi.IssuerCondition{
					Type:   cmapi.IssuerConditionReady,
					Status: cmmeta.ConditionFalse,
				})
			}
			assert.Equalf(
				t, tc.expectRotateCredentials, credentialsWereRotated,
				"unexpected rotatecredentials. expected: %v, actual: %v", tc.expectRotateCredentials, credentialsWereRotated,
			)
		})
	}
}
