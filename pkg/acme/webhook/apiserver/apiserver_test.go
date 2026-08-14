/*
Copyright 2022 The cert-manager Authors.

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

package apiserver

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/registry/challengepayload"
)

var (
	_ webhook.Solver = noOpSolver{}
)

type noOpSolver struct {
	name string
}

func (s noOpSolver) Name() string {
	return s.name
}

func (s noOpSolver) Present(_ *whapi.ChallengeRequest) error {
	return nil
}

func (s noOpSolver) CleanUp(_ *whapi.ChallengeRequest) error {
	return nil
}

func (s noOpSolver) Initialize(_ *rest.Config, _ <-chan struct{}) error {
	return nil
}

func newFakeRecommendedConfig() *genericapiserver.RecommendedConfig {
	cfg := genericapiserver.NewRecommendedConfig(Codecs)
	cfg.ExternalAddress = "192.168.10.4:443"
	cfg.LoopbackClientConfig = &rest.Config{}
	return cfg
}

func TestNewChallengeServer(t *testing.T) {
	tests := map[string]struct {
		cfg Config

		expErr bool
	}{
		"Single solver": {
			cfg: Config{
				GenericConfig: newFakeRecommendedConfig(),
				ExtraConfig: ExtraConfig{
					SolverGroup: "test-solvers.cert-manager.io",
					Solvers: []webhook.Solver{
						noOpSolver{name: "solver-1"},
					},
				},
			},
			expErr: false,
		},
		"Multiple solvers": {
			cfg: Config{
				GenericConfig: newFakeRecommendedConfig(),
				ExtraConfig: ExtraConfig{
					SolverGroup: "test-solvers.cert-manager.io",
					Solvers: []webhook.Solver{
						noOpSolver{name: "solver-1"},
						noOpSolver{name: "solver-2"},
					},
				},
			},
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server, err := test.cfg.Complete().New()
			if test.expErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			for _, solver := range test.cfg.ExtraConfig.Solvers {
				registeredKind := server.GenericAPIServer.EquivalentResourceRegistry.KindFor(
					schema.GroupVersionResource{
						Group:    test.cfg.ExtraConfig.SolverGroup,
						Version:  "v1alpha1",
						Resource: solver.Name(),
					},
					"",
				)
				expectedKind := challengepayload.NewREST(solver).
					GroupVersionKind(schema.GroupVersion{
						Group:   test.cfg.ExtraConfig.SolverGroup,
						Version: "v1alpha1",
					})
				require.Equal(t, expectedKind, registeredKind)
			}
		})
	}
}
