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

package dns

import (
	"flag"
	"fmt"
	"sync"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/test/apiserver"
)

func init() {
	vFlag := flag.Lookup("v")
	if vFlag != nil {
		utilruntime.Must(flag.Set("alsologtostderr", fmt.Sprintf("%t", true)))
		utilruntime.Must(vFlag.Value.Set("12"))
	}
}

type fixture struct {
	// testSolver is the actual DNS solver that is under test.
	// It is set when calling the NewFixture function.
	testSolver              webhook.Solver
	resolvedFQDN            string
	resolvedZone            string
	allowAmbientCredentials bool
	jsonConfig              *apiextensionsv1.JSON
	strictMode              bool
	useAuthoritative        *bool
	kubectlManifestsPath    string

	// testDNSServer is the address:port of the DNS server to send requests to
	// when validating that records are set as expected.
	// Ideally, for fast tests, this should be set to a DNS server that does
	// not cache queries.
	// This field can be set using the SetDNSServer Option.
	// Default: 8.8.8.8:53
	testDNSServer string

	// dnsName is the domain name used in the request in tests.
	// This field can be set using the SetDNSName Option.
	// Default: "example.com"
	dnsName string

	// dnsChallengeKey is the value of TXT record in tests.
	// This field can be set using the SetDNSChallengeKey Option.
	// Default: "123d=="
	dnsChallengeKey string

	setupLock   sync.Mutex
	environment *envtest.Environment
	// An admin user for running kubectl commands against this envtest
	// environment.
	adminUser *envtest.AuthenticatedUser
	clientset kubernetes.Interface

	pollInterval     time.Duration
	propagationLimit time.Duration
}

// RunConformance will execute all conformance tests using the supplied
// configuration These conformance tests should be run by all external DNS
// solver webhook implementations, see
// https://github.com/cert-manager/webhook-example
func (f *fixture) RunConformance(t *testing.T) {
	defer f.setup(t)()
	t.Run("Conformance", func(t *testing.T) {
		f.RunBasic(t)
		f.RunExtended(t)
	})
}

func (f *fixture) RunBasic(t *testing.T) {
	defer f.setup(t)()
	t.Run("Basic", func(t *testing.T) {
		t.Run("PresentRecord", f.TestBasicPresentRecord)
	})
}

func (f *fixture) RunExtended(t *testing.T) {
	defer f.setup(t)()
	t.Run("Extended", func(t *testing.T) {
		t.Run("DeletingOneRecordRetainsOthers", f.TestExtendedDeletingOneRecordRetainsOthers)
	})
}

func (f *fixture) setup(t *testing.T) func() {
	f.setupLock.Lock()
	defer f.setupLock.Unlock()

	if err := validate(f); err != nil {
		t.Fatalf("error validating test fixture configuration: %v", err)
	}

	env, stopFunc := apiserver.RunBareControlPlane(t)
	f.environment = env

	// An admin user instance for running kubectl against this envtest
	// environment.
	// Derived from the envtest global config which is configured with very high
	// QPS and Burst settings for rapid interactions with the API server.
	adminUser, err := env.AddUser(envtest.User{
		Name:   "envtest-admin",
		Groups: []string{"system:masters"},
	}, env.Config)
	if err != nil {
		t.Fatalf("unable to provision admin user: %s", err)
	}
	f.adminUser = adminUser

	cl, err := kubernetes.NewForConfig(env.Config)
	if err != nil {
		t.Fatal(err)
	}
	f.clientset = cl

	stopCh := make(chan struct{})

	if err := f.testSolver.Initialize(env.Config, stopCh); err != nil {
		t.Fatalf("error initializing solver: %v", err)
	}

	return func() {
		close(stopCh)
		stopFunc()
	}
}
