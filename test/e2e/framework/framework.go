/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package framework

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/api/core/v1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
	"github.com/jetstack/cert-manager/test/e2e/framework/util"
	"github.com/jetstack/cert-manager/test/e2e/framework/util/errors"
)

// DefaultConfig contains the default shared config the is likely parsed from
// command line arguments.
var DefaultConfig = &config.Config{}

// Framework supports common operations used by e2e tests; it will keep a client & a namespace for you.
type Framework struct {
	BaseName string

	Config *config.Config

	// KubeClientConfig which was used to create the connection.
	KubeClientConfig *rest.Config

	// Kubernetes API clientsets
	KubeClientSet          kubernetes.Interface
	CertManagerClientSet   clientset.Interface
	APIExtensionsClientSet apiextcs.Interface

	// Namespace in which all test resources should reside
	Namespace *v1.Namespace

	// To make sure that this framework cleans up after itself, no matter what,
	// we install a Cleanup action before each test and clear it after.  If we
	// should abort, the AfterSuite hook should run all Cleanup actions.
	cleanupHandle CleanupActionHandle
}

// NewDefaultFramework makes a new framework for you, similar to NewFramework.
// It uses the suite-wide 'DefaultConfig' which should be populated by the
// testing harness in test/e2e/e2e_test.go
func NewDefaultFramework(baseName string) *Framework {
	return NewFramework(baseName, DefaultConfig)
}

// NewFramework makes a new framework and sets up a BeforeEach/AfterEach for
// you (you can write additional before/after each functions).
// It uses the config provided to it for the duration of the tests.
func NewFramework(baseName string, cfg *config.Config) *Framework {
	f := &Framework{
		Config:   cfg,
		BaseName: baseName,
	}

	BeforeEach(f.BeforeEach)
	AfterEach(f.AfterEach)

	return f
}

// BeforeEach gets a client and makes a namespace.
func (f *Framework) BeforeEach() {
	f.cleanupHandle = AddCleanupAction(f.AfterEach)

	By("Creating a kubernetes client")
	kubeConfig, err := util.LoadConfig(f.Config.KubeConfig, f.Config.KubeContext)
	Expect(err).NotTo(HaveOccurred())
	f.KubeClientConfig = kubeConfig

	f.KubeClientSet, err = kubernetes.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Creating an API extensions client")
	f.APIExtensionsClientSet, err = apiextcs.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Creating a cert manager client")
	f.CertManagerClientSet, err = clientset.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Building a namespace api object")
	f.Namespace, err = f.CreateKubeNamespace(f.BaseName)
	Expect(err).NotTo(HaveOccurred())

	By("Building a ResourceQuota api object")
	_, err = f.CreateKubeResourceQuota()
	Expect(err).NotTo(HaveOccurred())
}

// AfterEach deletes the namespace, after reading its events.
func (f *Framework) AfterEach() {
	RemoveCleanupAction(f.cleanupHandle)

	By("Deleting test namespace")
	err := f.DeleteKubeNamespace(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	By("Waiting for test namespace to no longer exist")
	err = f.WaitForKubeNamespaceNotExist(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())
}

// RequireGlobalAddon calls Setup on the given addon.
// This should be called in specs or describe blocks that require access to any
// of the global/shared addons in order to ensure their details are available.
// This method should only ever be called with addons defined in the 'addons' that
// are present in the 'globals' variable, as they will not be Provisioned properly
// otherwise.
func (f *Framework) RequireGlobalAddon(a addon.Addon) {
	BeforeEach(func() {
		By("Setting up access for global shared addon")
		err := a.Setup(f.Config)
		Expect(err).NotTo(HaveOccurred())
	})
}

// RequireAddon calls the Setup and Provision method on the given addon, failing
// the spec if provisioning fails.
// It returns the addons deprovision function as a convinience.
func (f *Framework) RequireAddon(a addon.Addon) {
	BeforeEach(func() {
		By("Provisioning test-scoped addon")
		err := a.Setup(f.Config)
		if errors.IsSkip(err) {
			Skipf("Skipping test as addon could not be setup: %v", err)
		}
		Expect(err).NotTo(HaveOccurred())

		err = a.Provision()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if !f.Config.Cleanup {
			return
		}
		err := a.Deprovision()
		Expect(err).NotTo(HaveOccurred())
	})
}

// CertManagerDescribe is a wrapper function for ginkgo describe. Adds namespacing.
func CertManagerDescribe(text string, body func()) bool {
	return Describe("[cert-manager] "+text, body)
}

func ConformanceDescribe(text string, body func()) bool {
	return Describe("[Conformance] "+text, body)
}
