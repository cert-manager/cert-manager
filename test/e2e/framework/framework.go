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

package framework

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/api/core/v1"
	api "k8s.io/api/core/v1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	certmgrscheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
	"github.com/jetstack/cert-manager/test/e2e/framework/util"
	"github.com/jetstack/cert-manager/test/e2e/framework/util/errors"
)

// TODO: this really should be done somewhere in cert-manager proper
var Scheme = runtime.NewScheme()

func init() {
	kscheme.AddToScheme(Scheme)
	certmgrscheme.AddToScheme(Scheme)
}

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

	// controller-runtime client for newer controllers
	CRClient crclient.Client

	// Namespace in which all test resources should reside
	Namespace *v1.Namespace

	// To make sure that this framework cleans up after itself, no matter what,
	// we install a Cleanup action before each test and clear it after.  If we
	// should abort, the AfterSuite hook should run all Cleanup actions.
	cleanupHandle CleanupActionHandle

	requiredAddons []addon.Addon
	helper         *helper.Helper
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

	f.helper = helper.NewHelper(cfg)
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

	By("Creating a controller-runtime client")
	f.CRClient, err = crclient.New(kubeConfig, crclient.Options{Scheme: Scheme})
	Expect(err).NotTo(HaveOccurred())

	By("Building a namespace api object")
	f.Namespace, err = f.CreateKubeNamespace(f.BaseName)
	Expect(err).NotTo(HaveOccurred())

	By("Using the namespace " + f.Namespace.Name)

	By("Building a ResourceQuota api object")
	_, err = f.CreateKubeResourceQuota()
	Expect(err).NotTo(HaveOccurred())

	f.helper.CMClient = f.CertManagerClientSet
	f.helper.KubeClient = f.KubeClientSet
}

// AfterEach deletes the namespace, after reading its events.
func (f *Framework) AfterEach() {
	RemoveCleanupAction(f.cleanupHandle)

	f.printAddonLogs()

	By("Deleting test namespace")
	err := f.DeleteKubeNamespace(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	By("Waiting for test namespace to no longer exist")
	err = f.WaitForKubeNamespaceNotExist(f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())
}

func (f *Framework) printAddonLogs() {
	if CurrentGinkgoTestDescription().Failed {
		for _, a := range f.requiredAddons {
			if a, ok := a.(loggableAddon); ok {
				l, err := a.Logs()
				Expect(err).NotTo(HaveOccurred())

				// TODO: replace with writing logs to a file
				log.Logf("Got pod logs for addon: \n%s", l)
			}
		}
	}
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

type loggableAddon interface {
	Logs() (string, error)
}

// RequireAddon calls the Setup and Provision method on the given addon, failing
// the spec if provisioning fails.
func (f *Framework) RequireAddon(a addon.Addon) {
	f.requiredAddons = append(f.requiredAddons, a)

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

func (f *Framework) Helper() *helper.Helper {
	return f.helper
}

func (f *Framework) CertificateDurationValid(c *v1alpha1.Certificate, duration time.Duration) {
	By("Verifying TLS certificate exists")
	secret, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(c.Spec.SecretName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	certBytes, ok := secret.Data[api.TLSCertKey]
	if !ok {
		Failf("No certificate data found for Certificate %q", c.Name)
	}
	cert, err := pki.DecodeX509CertificateBytes(certBytes)
	Expect(err).NotTo(HaveOccurred())
	By("Verifying that the duration is valid")
	if cert.NotAfter.Sub(cert.NotBefore) != duration {
		Failf("Expected duration of %s, got %s [NotBefore: %s, NotAfter: %s]", duration, cert.NotAfter.Sub(cert.NotBefore), cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
}

// CertManagerDescribe is a wrapper function for ginkgo describe. Adds namespacing.
func CertManagerDescribe(text string, body func()) bool {
	return Describe("[cert-manager] "+text, body)
}

func ConformanceDescribe(text string, body func()) bool {
	return Describe("[Conformance] "+text, body)
}
