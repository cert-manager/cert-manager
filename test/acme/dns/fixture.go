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
	"flag"
	"fmt"
	"k8s.io/client-go/kubernetes"
	"sync"
	"testing"
	"time"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/testing_frameworks/integration"

	"github.com/jetstack/cert-manager/pkg/acme/webhook"
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
	testSolver webhook.Solver

	resolvedFQDN            string
	resolvedZone            string
	allowAmbientCredentials bool
	jsonConfig              *v1beta1.JSON
	strictMode              bool
	useAuthoritative        *bool
	kubectlManifestsPath    string
	binariesPath            string

	// testDNSServer is the address:port of the DNS server to send requests to
	// when validating that records are set as expected.
	// Ideally, for fast tests, this should be set to a DNS server that does
	// not cache queries.
	// This field can be set using the SetDNSServer Option.
	// Default: 8.8.8.8:53
	testDNSServer string

	// controlPlane is a reference to the control plane that is used to run the
	// test suite.
	// It is constructed when a Run* method is called.
	controlPlane *integration.ControlPlane
	restConfig   *rest.Config
	clientset    kubernetes.Interface
	kubectl      *integration.KubeCtl
	setupLock    sync.Mutex

	pollInterval     time.Duration
	propagationLimit time.Duration
}

var DefaultKubeAPIServerFlags = []string{
	"--etcd-servers={{ if .EtcdURL }}{{ .EtcdURL.String }}{{ end }}",
	"--cert-dir={{ .CertDir }}",
	"--insecure-port={{ if .URL }}{{ .URL.Port }}{{ end }}",
	"--insecure-bind-address={{ if .URL }}{{ .URL.Hostname }}{{ end }}",
	"--secure-port={{ if .SecurePort }}{{ .SecurePort }}{{ end }}",
	"--admission-control=AlwaysAdmit",
}

// Setup will set up the test fixture by running kube-apiserver and etcd.
// One instance of the apiserver and etcd will be shared throughout all of the
// suite.
// The first time this function is called, the function that is returned will
// be the control plane's Stop function. Subsequent calls to setup will return
// a function that does nothing. This allows all the Run* functions to call
// setup, and defer cleaning up the fixture, but only the first 'entrypoint'
// Run function will actually clean up the apiserver.
func (f *fixture) setup(t *testing.T) func() error {
	f.setupLock.Lock()
	defer f.setupLock.Unlock()

	if err := validate(f); err != nil {
		t.Fatalf("error validating test fixture configuration: %v", err)
	}

	if f.controlPlane != nil {
		return func() error { return nil }
	}
	f.controlPlane = &integration.ControlPlane{}
	f.controlPlane.APIServer = &integration.APIServer{
		Args: DefaultKubeAPIServerFlags,
		Path: f.binariesPath + "/kube-apiserver",
	}
	f.controlPlane.Etcd = &integration.Etcd{
		Path: f.binariesPath + "/etcd",
	}
	if err := f.controlPlane.Start(); err != nil {
		t.Fatalf("error starting apiserver: %v", err)
	}
	t.Logf("started apiserver on %q", f.controlPlane.APIURL())
	// Create the *rest.Config for creating new clients
	f.restConfig = &rest.Config{
		Host: f.controlPlane.APIURL().Host,
		// gotta go fast during tests -- we don't really care about overwhelming our test API server
		QPS:   1000.0,
		Burst: 2000.0,
	}
	var err error
	if f.clientset, err = kubernetes.NewForConfig(f.restConfig); err != nil {
		t.Fatalf("error constructing clientset: %v", err)
	}
	f.kubectl = f.controlPlane.KubeCtl()
	f.kubectl.Path = f.binariesPath + "/kubectl"

	stopCh := make(chan struct{})
	f.testSolver.Initialize(f.restConfig, stopCh)
	return func() error {
		close(stopCh)
		return f.controlPlane.Stop()
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
