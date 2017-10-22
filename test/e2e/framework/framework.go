/*
Copyright 2017 Jetstack Ltd.
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
	"k8s.io/api/core/v1"
	corev1 "k8s.io/api/core/v1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/test/util"
)

const (
	podName = "test-cert-manager"
)

// Framework supports common operations used by e2e tests; it will keep a client & a namespace for you.
type Framework struct {
	BaseName string

	// A Kubernetes and Service Catalog client
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

// NewFramework makes a new framework and sets up a BeforeEach/AfterEach for
// you (you can write additional before/after each functions).
func NewDefaultFramework(baseName string) *Framework {
	f := &Framework{
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
	kubeConfig, err := LoadConfig(TestContext.KubeConfig, TestContext.KubeContext)
	Expect(err).NotTo(HaveOccurred())

	f.KubeClientSet, err = kubernetes.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Creating an API extensions client")
	f.APIExtensionsClientSet, err = apiextcs.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Creating a cert manager client")
	certManagerConfig, err := LoadConfig(TestContext.CertManagerConfig, TestContext.CertManagerContext)
	Expect(err).NotTo(HaveOccurred())
	f.CertManagerClientSet, err = clientset.NewForConfig(certManagerConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Building a namespace api object")
	f.Namespace, err = CreateKubeNamespace(f.BaseName, f.KubeClientSet)
	Expect(err).NotTo(HaveOccurred())

	By("Building an Issuer CustomResourceDefinition api object")
	err = CreateIssuerCRD(f.APIExtensionsClientSet)
	Expect(err).NotTo(HaveOccurred())

	By("Building a ClusterIssuer CustomResourceDefinition api object")
	err = CreateClusterIssuerCRD(f.APIExtensionsClientSet)
	Expect(err).NotTo(HaveOccurred())

	By("Building an Certificate CustomResourceDefinition api object")
	err = CreateCertificateCRD(f.APIExtensionsClientSet)
	Expect(err).NotTo(HaveOccurred())

	By("Creating a cert-manager pod")
	pod, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Create(util.NewCertManagerControllerPod(podName, "--cluster-resource-namespace="+f.Namespace.Name, "--v=4"))
	Expect(err).NotTo(HaveOccurred())

	By("Waiting for cert-manager to be running")
	err = WaitForPodRunningInNamespace(f.KubeClientSet, pod)
	Expect(err).NotTo(HaveOccurred())
}

// AfterEach deletes the namespace, after reading its events.
func (f *Framework) AfterEach() {
	RemoveCleanupAction(f.cleanupHandle)

	By("Retrieving the cert-manager pod logs")
	b, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).GetLogs(podName, &corev1.PodLogOptions{}).Do().Raw()
	Expect(err).NotTo(HaveOccurred())
	_, err = GinkgoWriter.Write(b)
	Expect(err).NotTo(HaveOccurred())

	By("Deleting test namespace")
	err = DeleteKubeNamespace(f.KubeClientSet, f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())

	By("Deleting Issuer CustomResourceDefinition")
	err = DeleteIssuerCRD(f.APIExtensionsClientSet)
	Expect(err).NotTo(HaveOccurred())

	By("Deleting ClusterIssuer CustomResourceDefinition")
	err = DeleteClusterIssuerCRD(f.APIExtensionsClientSet)
	Expect(err).NotTo(HaveOccurred())

	By("Deleting Certificate CustomResourceDefinition")
	err = DeleteCertificateCRD(f.APIExtensionsClientSet)
	Expect(err).NotTo(HaveOccurred())

	By("Waiting for Issuer CRD to no longer exist")
	err = util.WaitForCRDToNotExist(f.APIExtensionsClientSet.ApiextensionsV1beta1().CustomResourceDefinitions(), issuerCrd().Name)
	Expect(err).NotTo(HaveOccurred())
	By("Waiting for ClusterIssuer CRD to no longer exist")
	err = util.WaitForCRDToNotExist(f.APIExtensionsClientSet.ApiextensionsV1beta1().CustomResourceDefinitions(), clusterIssuerCrd().Name)
	Expect(err).NotTo(HaveOccurred())
	By("Waiting for Certificate CRD to no longer exist")
	err = util.WaitForCRDToNotExist(f.APIExtensionsClientSet.ApiextensionsV1beta1().CustomResourceDefinitions(), certificateCrd().Name)
	Expect(err).NotTo(HaveOccurred())
	By("Waiting for test namespace to no longer exist")
	err = WaitForKubeNamespaceNotExist(f.KubeClientSet, f.Namespace.Name)
	Expect(err).NotTo(HaveOccurred())
}

// Wrapper function for ginkgo describe.  Adds namespacing.
func CertManagerDescribe(text string, body func()) bool {
	return Describe("[cert-manager] "+text, body)
}
