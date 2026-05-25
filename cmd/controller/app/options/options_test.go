/*
Copyright 2021 The cert-manager Authors.

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

package options

import (
	"testing"

	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	defaults "github.com/cert-manager/cert-manager/internal/apis/config/controller/v1alpha1"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestEnabledControllers(t *testing.T) {
	tests := map[string]struct {
		controllers []string
		namespace   string
		expEnabled  sets.Set[string]
	}{
		"if no controllers enabled, return empty": {
			controllers: []string{},
			expEnabled:  sets.New[string](),
		},
		"if some controllers enabled, return list": {
			controllers: []string{"foo", "bar"},
			expEnabled:  sets.New("foo", "bar"),
		},
		"if some controllers enabled, one then disabled, return list without disabled": {
			controllers: []string{"foo", "bar", "-foo"},
			expEnabled:  sets.New("bar"),
		},
		"if all default controllers enabled, return all default controllers": {
			controllers: []string{"*"},
			expEnabled:  sets.New(defaults.DefaultEnabledControllers...),
		},
		"if all controllers enabled, some disabled, return all controllers without disabled": {
			controllers: []string{"*", "-clusterissuers", "-issuers"},
			expEnabled:  sets.New(defaults.DefaultEnabledControllers...).Delete("clusterissuers", "issuers"),
		},
		"if only disabled controllers are specified, implicitly enable all default controllers": {
			controllers: []string{"-clusterissuers", "-issuers"},
			expEnabled:  sets.New(defaults.DefaultEnabledControllers...).Delete("clusterissuers", "issuers"),
		},
		"if namespace set, remove cluster-scoped controllers": {
			controllers: []string{"*"},
			namespace:   "test-ns",
			expEnabled:  sets.New(defaults.DefaultEnabledControllers...).Delete(defaults.ClusterScopedControllers...),
		},
		"if namespace set with explicit controllers, preserve non-cluster-scoped and remove cluster-scoped": {
			controllers: []string{"issuers", "clusterissuers"},
			namespace:   "test-ns",
			expEnabled:  sets.New("issuers"),
		},
		"if namespace set with wildcard and disabled controllers, remove cluster-scoped and disabled": {
			controllers: []string{"*", "-issuers"},
			namespace:   "test-ns",
			expEnabled:  sets.New(defaults.DefaultEnabledControllers...).Delete(defaults.ClusterScopedControllers...).Delete("issuers"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o := config.ControllerConfiguration{
				Controllers: test.controllers,
				Namespace:   test.namespace,
			}

			got := EnabledControllers(&o)
			if !got.Equal(test.expEnabled) {
				t.Errorf("got unexpected enabled controllers, exp=%v got=%v",
					sets.List(test.expEnabled), sets.List(got))
			}
		})
	}
}
