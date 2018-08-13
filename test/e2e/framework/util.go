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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

const (
	// How often to poll for conditions
	Poll = 2 * time.Second

	// Default time to wait for operations to complete
	defaultTimeout = 30 * time.Second

	longTimeout = 5 * time.Minute
)

func nowStamp() string {
	return time.Now().Format(time.StampMilli)
}

func log(level string, format string, args ...interface{}) {
	fmt.Fprintf(GinkgoWriter, nowStamp()+": "+level+": "+format+"\n", args...)
}

func Logf(format string, args ...interface{}) {
	log("INFO", format, args...)
}

func Failf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log("INFO", msg)
	Fail(nowStamp()+": "+msg, 1)
}

func Skipf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log("INFO", msg)
	Skip(nowStamp() + ": " + msg)
}

func RestclientConfig(config, context string) (*api.Config, error) {
	Logf(">>> config: %s\n", config)
	if config == "" {
		return nil, fmt.Errorf("Config file must be specified to load client config")
	}
	c, err := clientcmd.LoadFromFile(config)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err.Error())
	}
	if context != "" {
		Logf(">>> context: %s\n", context)
		c.CurrentContext = context
	}
	return c, nil
}

type ClientConfigGetter func() (*rest.Config, error)

func LoadConfig(config, context string) (*rest.Config, error) {
	c, err := RestclientConfig(config, context)
	if err != nil {
		return nil, err
	}
	return clientcmd.NewDefaultClientConfig(*c, &clientcmd.ConfigOverrides{}).ClientConfig()
}

// unique identifier of the e2e run
var RunId = uuid.NewUUID()

// apiVersion: apiextensions.k8s.io/v1beta1
// kind: CustomResourceDefinition
// metadata:
//   name: certificates.certmanager.k8s.io
// spec:
//   group: certmanager.k8s.io
//   version: v1alpha1
//   names:
//     kind: Certificate
//     plural: certificates
//   scope: Namespaced # Can also be cluster level using "Cluster"
// ---
// apiVersion: apiextensions.k8s.io/v1beta1
// kind: CustomResourceDefinition
// metadata:
//   name: issuers.certmanager.k8s.io
// spec:
//   group: certmanager.k8s.io
//   version: v1alpha1
//   names:
//     kind: Issuer
//     plural: issuers
//   scope: Namespaced # Can also be cluster level using "Cluster"

func certificateCrd() *apiext.CustomResourceDefinition {
	return &apiext.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "certificates.certmanager.k8s.io",
		},
		Spec: apiext.CustomResourceDefinitionSpec{
			Group:   "certmanager.k8s.io",
			Version: "v1alpha1",
			Names: apiext.CustomResourceDefinitionNames{
				Kind:   "Certificate",
				Plural: "certificates",
			},
			Scope: apiext.NamespaceScoped,
		},
	}
}

func issuerCrd() *apiext.CustomResourceDefinition {
	return &apiext.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "issuers.certmanager.k8s.io",
		},
		Spec: apiext.CustomResourceDefinitionSpec{
			Group:   "certmanager.k8s.io",
			Version: "v1alpha1",
			Names: apiext.CustomResourceDefinitionNames{
				Kind:   "Issuer",
				Plural: "issuers",
			},
			Scope: apiext.NamespaceScoped,
		},
	}
}

func clusterIssuerCrd() *apiext.CustomResourceDefinition {
	return &apiext.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "clusterissuers.certmanager.k8s.io",
		},
		Spec: apiext.CustomResourceDefinitionSpec{
			Group:   "certmanager.k8s.io",
			Version: "v1alpha1",
			Names: apiext.CustomResourceDefinitionNames{
				Kind:   "ClusterIssuer",
				Plural: "clusterissuers",
			},
			Scope: apiext.ClusterScoped,
		},
	}
}

func CreateCertificateCRD(c apiextcs.Interface) error {
	_, err := c.ApiextensionsV1beta1().CustomResourceDefinitions().Create(certificateCrd())
	return err
}

func DeleteCertificateCRD(c apiextcs.Interface) error {
	return c.ApiextensionsV1beta1().CustomResourceDefinitions().Delete(certificateCrd().Name, nil)
}

func CreateIssuerCRD(c apiextcs.Interface) error {
	_, err := c.ApiextensionsV1beta1().CustomResourceDefinitions().Create(issuerCrd())
	return err
}

func DeleteIssuerCRD(c apiextcs.Interface) error {
	return c.ApiextensionsV1beta1().CustomResourceDefinitions().Delete(issuerCrd().Name, nil)
}

func CreateClusterIssuerCRD(c apiextcs.Interface) error {
	_, err := c.ApiextensionsV1beta1().CustomResourceDefinitions().Create(clusterIssuerCrd())
	return err
}

func DeleteClusterIssuerCRD(c apiextcs.Interface) error {
	return c.ApiextensionsV1beta1().CustomResourceDefinitions().Delete(clusterIssuerCrd().Name, nil)
}

func CreateKubeNamespace(baseName string, c kubernetes.Interface) (*v1.Namespace, error) {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("e2e-tests-%v-", baseName),
		},
	}

	quota := &v1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("e2e-tests-%v-", baseName),
		},
		Spec: v1.ResourceQuotaSpec{
			Hard: v1.ResourceList{
				"cpu":             resource.MustParse("16"),
				"limits.cpu":      resource.MustParse("16"),
				"requests.cpu":    resource.MustParse("16"),
				"memory":          resource.MustParse("32G"),
				"limits.memory":   resource.MustParse("32G"),
				"requests.memory": resource.MustParse("32G"),
			},
		},
	}

	// Be robust about making the namespace creation call.
	var got *v1.Namespace
	err := wait.PollImmediate(Poll, defaultTimeout, func() (bool, error) {
		var err error
		got, err = c.Core().Namespaces().Create(ns)
		if err != nil {
			Logf("Unexpected error while creating namespace: %v", err)
			return false, nil
		}
		Logf("Created namespace: %v", got.Name)

		gotQuota, err := c.Core().ResourceQuotas(got.Name).Create(quota)
		if err != nil {
			Logf("Unexpected error while creating quota: %v", err)
			return false, nil
		}
		Logf("Created quota: %v", gotQuota.Name)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return got, nil
}

func DeleteKubeNamespace(c kubernetes.Interface, namespace string) error {
	return c.Core().Namespaces().Delete(namespace, nil)
}

func ExpectNoError(err error, explain ...interface{}) {
	if err != nil {
		Logf("Unexpected error occurred: %v", err)
	}
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), explain...)
}

func WaitForKubeNamespaceNotExist(c kubernetes.Interface, namespace string) error {
	return wait.PollImmediate(Poll, time.Minute*2, namespaceNotExist(c, namespace))
}

func namespaceNotExist(c kubernetes.Interface, namespace string) wait.ConditionFunc {
	return func() (bool, error) {
		_, err := c.CoreV1().Namespaces().Get(namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return false, nil
	}
}

// Waits default amount of time (PodStartTimeout) for the specified pod to become running.
// Returns an error if timeout occurs first, or pod goes in to failed state.
func WaitForPodRunningInNamespace(c kubernetes.Interface, pod *v1.Pod) error {
	if pod.Status.Phase == v1.PodRunning {
		return nil
	}
	return waitTimeoutForPodRunningInNamespace(c, pod.Name, pod.Namespace, defaultTimeout)
}

func waitTimeoutForPodRunningInNamespace(c kubernetes.Interface, podName, namespace string, timeout time.Duration) error {
	return wait.PollImmediate(Poll, defaultTimeout, podRunning(c, podName, namespace))
}

func podRunning(c kubernetes.Interface, podName, namespace string) wait.ConditionFunc {
	return func() (bool, error) {
		pod, err := c.CoreV1().Pods(namespace).Get(podName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		switch pod.Status.Phase {
		case v1.PodRunning:
			return true, nil
		case v1.PodFailed, v1.PodSucceeded:
			return false, fmt.Errorf("pod ran to completion")
		}
		return false, nil
	}
}
