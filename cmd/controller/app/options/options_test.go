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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"

	//"github.com/cert-manager/cert-manager/controller-binary/app/options"
	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	defaults "github.com/cert-manager/cert-manager/internal/apis/config/controller/v1alpha1"
	"github.com/cert-manager/cert-manager/internal/apis/config/controller/validation"
)

func TestEnabledControllers(t *testing.T) {
	tests := map[string]struct {
		controllers []string
		expEnabled  sets.Set[string]
	}{
		"if no controllers enabled, return empty": {
			controllers: []string{},
			expEnabled:  sets.New[string](),
		},
		"if some controllers enabled, return list": {
			controllers: []string{"foo", "bar"},
			expEnabled:  sets.New[string]("foo", "bar"),
		},
		"if some controllers enabled, one then disabled, return list without disabled": {
			controllers: []string{"foo", "bar", "-foo"},
			expEnabled:  sets.New[string]("bar"),
		},
		"if all default controllers enabled, return all default controllers": {
			controllers: []string{"*"},
			expEnabled:  sets.New[string](defaults.DefaultEnabledControllers...),
		},
		"if all controllers enabled, some diabled, return all controllers with disabled": {
			controllers: []string{"*", "-clusterissuers", "-issuers"},
			expEnabled:  sets.New[string](defaults.DefaultEnabledControllers...).Delete("clusterissuers", "issuers"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o := config.ControllerConfiguration{
				Controllers: test.controllers,
			}

			got := EnabledControllers(&o)
			if !got.Equal(test.expEnabled) {
				t.Errorf("got unexpected enabled, exp=%s got=%s",
					test.expEnabled, got)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		DNS01RecursiveServers []string
		expError              string
	}{
		"if valid dns servers with ip address and port, return no errors": {
			DNS01RecursiveServers: []string{"192.168.0.1:53", "10.0.0.1:5353"},
			expError:              "",
		},
		"if valid DNS servers with DoH server addresses including https prefix, return no errors": {
			DNS01RecursiveServers: []string{"https://dns.example.com", "https://doh.server"},
			expError:              "",
		},
		"if invalid DNS server format due to missing https prefix, return 'invalid DNS server' error": {
			DNS01RecursiveServers: []string{"dns.example.com"},
			expError:              "invalid DNS server",
		},
		"if invalid DNS server format due to invalid IP address length and no port, return 'invalid DNS server' error": {
			DNS01RecursiveServers: []string{"192.168.0.1.53"},
			expError:              "invalid DNS server",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o, _ := NewControllerConfiguration()
			o.ACMEDNS01Config.RecursiveNameservers = test.DNS01RecursiveServers

			err := validation.ValidateControllerConfiguration(o)
			if test.expError != "" {
				if err == nil || !strings.Contains(err.Error(), test.expError) {
					t.Errorf("expected error containing '%s', but got: %v", test.expError, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
