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

package dns

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	"github.com/jetstack/cert-manager/pkg/acme/webhook"
)

// Option applies a configuration option to the test fixture being built
type Option func(*fixture)

// NewFixture constructs a new *fixture, applying the given Options before
// returning.
func NewFixture(solver webhook.Solver, opts ...Option) *fixture {
	f := &fixture{
		testSolver: solver,
	}
	for _, o := range opts {
		o(f)
	}
	applyDefaults(f)
	return f
}

func applyDefaults(f *fixture) {
	if f.testDNSServer == "" {
		f.testDNSServer = "8.8.8.8:53"
	}
	if f.resolvedFQDN == "" {
		f.resolvedFQDN = "cert-manager-dns01-tests." + f.resolvedZone
	}
	runfiles := os.Getenv("TEST_SRCDIR")
	if f.binariesPath == "" {
		if runfiles != "" {
			f.binariesPath = runfiles + "/com_github_jetstack_cert_manager/hack/bin"
		}
	}
	if f.jsonConfig == nil {
		if f.kubectlManifestsPath != "" {
			d, err := ioutil.ReadFile(f.kubectlManifestsPath + "/config.json")
			if err == nil {
				f.jsonConfig = &extapi.JSON{
					Raw: d,
				}
			}
		}
	}
	if f.useAuthoritative == nil {
		trueVal := true
		f.useAuthoritative = &trueVal
	}
}

func validate(f *fixture) error {
	var errs []error
	if f.resolvedFQDN == "" {
		errs = append(errs, fmt.Errorf("resolvedFQDN must be provided"))
	}
	if !strings.HasSuffix(f.resolvedFQDN, ".") {
		errs = append(errs, fmt.Errorf("resolvedFQDN must end with a '.'"))
	}
	if f.resolvedZone == "" {
		errs = append(errs, fmt.Errorf("resolvedZone must be provided"))
	}
	if f.binariesPath == "" {
		errs = append(errs, fmt.Errorf("binariesPath must be provided"))
	}
	if f.jsonConfig == nil {
		errs = append(errs, fmt.Errorf("jsonConfig must be provided"))
	}
	if f.useAuthoritative == nil {
		errs = append(errs, fmt.Errorf("useAuthoritative must be provided"))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%v", errs)
	}

	return nil
}

func SetResolvedFQDN(s string) Option {
	return func(f *fixture) {
		f.resolvedFQDN = s
	}
}

func SetResolvedZone(s string) Option {
	return func(f *fixture) {
		f.resolvedZone = s
	}
}

func SetAllowAmbientCredentials(b bool) Option {
	return func(f *fixture) {
		f.allowAmbientCredentials = b
	}
}

func SetConfig(i interface{}) Option {
	return func(f *fixture) {
		d, err := json.Marshal(i)
		if err != nil {
			panic(err)
		}
		f.jsonConfig = &extapi.JSON{Raw: d}
	}
}

func SetStrict(s bool) Option {
	return func(f *fixture) {
		f.strictMode = s
	}
}

func SetUseAuthoritative(s bool) Option {
	return func(f *fixture) {
		f.useAuthoritative = &s
	}
}

func SetManifestPath(s string) Option {
	return func(f *fixture) {
		f.kubectlManifestsPath = s
	}
}

func SetDNSServer(s string) Option {
	return func(f *fixture) {
		f.testDNSServer = s
	}
}

func SetBinariesPath(s string) Option {
	return func(f *fixture) {
		f.binariesPath = s
	}
}

func SetPollInterval(d time.Duration) Option {
	return func(f *fixture) {
		f.pollInterval = d
	}
}

func SetPropagationLimit(d time.Duration) Option {
	return func(f *fixture) {
		f.propagationLimit = d
	}
}
