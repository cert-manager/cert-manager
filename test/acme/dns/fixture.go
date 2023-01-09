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
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/rfc2136"
	"github.com/cert-manager/cert-manager/test/internal/apiserver"
)

func init() {
	vFlag := flag.Lookup("v")
	if vFlag != nil {
		flag.Set("alsologtostderr", fmt.Sprintf("%t", true))
		vFlag.Value.Set("12")
	}
}

type fixture struct {
	// testSolver is the actual DNS solver that is under test.
	// It is set when calling the NewFixture function.
	testSolver     webhook.Solver
	testSolverType string

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
	clientset   kubernetes.Interface

	pollInterval     time.Duration
	propagationLimit time.Duration
}

func (f *fixture) setup(t *testing.T) func() {
	f.setupLock.Lock()
	defer f.setupLock.Unlock()

	if err := validate(f); err != nil {
		t.Fatalf("error validating test fixture configuration: %v", err)
	}

	env, stopFunc := apiserver.RunBareControlPlane(t)
	f.environment = env

	cl, err := kubernetes.NewForConfig(env.Config)
	if err != nil {
		t.Fatal(err)
	}
	f.clientset = cl

	stopCh := make(chan struct{})

	var testSolver webhook.Solver
	switch f.testSolverType {
	case rfc2136.SolverName:
		cl, err := kubernetes.NewForConfig(env.Config)
		if err != nil {
			t.Errorf("error initializing solver: %#+v", err)
		}

		// obtain a secret lister and start the informer factory to populate the
		// secret cache
		factory := informers.NewSharedInformerFactoryWithOptions(cl, time.Minute*5)
		secretLister := factory.Core().V1().Secrets().Lister()
		factory.Start(stopCh)
		factory.WaitForCacheSync(stopCh)
		testSolver = rfc2136.New(rfc2136.WithSecretsLister(secretLister))
		f.testSolver = testSolver
	default:
		t.Errorf("unknown solver type: %s", f.testSolverType)
	}

	testSolver.Initialize(env.Config, stopCh)

	return func() {
		close(stopCh)
		stopFunc()
	}
}

// RunConformance will execute all conformance tests using the supplied
// configuration
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
