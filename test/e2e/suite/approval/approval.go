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

package approval

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	crdapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	crdclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	testutil "github.com/cert-manager/cert-manager/test/e2e/framework/util"
	e2eutil "github.com/cert-manager/cert-manager/test/e2e/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// This test ensures that the approval condition may only be set by users who
// have the correct RBAC permissions.
var _ = framework.CertManagerDescribe("Approval CertificateRequests", func() {
	f := framework.NewDefaultFramework("approval-certificaterequests")

	var (
		sa       *corev1.ServiceAccount
		saclient clientset.Interface
		request  *cmapi.CertificateRequest

		crd       *crdapi.CustomResourceDefinition
		crdclient crdclientset.Interface
		group     string
	)

	JustBeforeEach(func() {
		var err error
		crdclient, err = crdclientset.NewForConfig(f.KubeClientConfig)
		Expect(err).NotTo(HaveOccurred())
		group = e2eutil.RandomSubdomain("example.io")

		sa, err = f.KubeClientSet.CoreV1().ServiceAccounts(f.Namespace.Name).Create(context.TODO(), &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-sa-",
				Namespace:    f.Namespace.Name,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		role, err := f.KubeClientSet.RbacV1().Roles(f.Namespace.Name).Create(context.TODO(), &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "certificaterequest-creator-",
				Namespace:    f.Namespace.Name,
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"create"},
					APIGroups: []string{"cert-manager.io"},
					Resources: []string{"certificaterequests"},
				},
				{
					Verbs:     []string{"update"},
					APIGroups: []string{"cert-manager.io"},
					Resources: []string{"certificaterequests/status"},
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating certificaterequest-creator rolebinding for ServiceAccount")
		_, err = f.KubeClientSet.RbacV1().RoleBindings(f.Namespace.Name).Create(context.TODO(), &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "certificaterequest-creator-",
				Namespace:    f.Namespace.Name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      sa.Name,
					Namespace: f.Namespace.Name,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     role.Name,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		err = wait.PollImmediate(time.Second, time.Second*10,
			func() (bool, error) {
				sa, err = f.KubeClientSet.CoreV1().ServiceAccounts(f.Namespace.Name).Get(context.TODO(), sa.Name, metav1.GetOptions{})
				if err != nil {
					return false, err
				}

				if len(sa.Secrets) == 0 {
					return false, nil
				}

				return true, nil
			},
		)
		Expect(err).NotTo(HaveOccurred())

		By("Building ServiceAccount kubernetes clientset")
		sec, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Get(context.TODO(), sa.Secrets[0].Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		kubeConfig, err := testutil.LoadConfig(f.Config.KubeConfig, f.Config.KubeContext)
		Expect(err).NotTo(HaveOccurred())

		kubeConfig.BearerToken = fmt.Sprintf("%s", sec.Data["token"])
		kubeConfig.CertData = nil
		kubeConfig.KeyData = nil

		saclient, err = clientset.NewForConfig(kubeConfig)
		Expect(err).NotTo(HaveOccurred())

		csr, _, err := gen.CSR(x509.RSA)
		Expect(err).NotTo(HaveOccurred())

		request = gen.CertificateRequest("",
			gen.SetCertificateRequestNamespace(f.Namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  "test-issuer",
				Kind:  "Issuer",
				Group: group,
			}),
		)
		request.GenerateName = "test-request-"

		request, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).Create(context.TODO(), request, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	JustAfterEach(func() {
		err := f.KubeClientSet.CoreV1().ServiceAccounts(f.Namespace.Name).Delete(context.TODO(), sa.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Delete(context.TODO(), request.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		if crd != nil {
			By("Removing CustomResource Definition")
			err = crdclient.ApiextensionsV1().CustomResourceDefinitions().Delete(context.TODO(), crd.Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
		crd = nil
	})

	It("attempting to approve a certificate request without the approve permission should error", func() {
		approvedCR := request.DeepCopy()
		apiutil.SetCertificateRequestCondition(approvedCR, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err := saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), approvedCR, metav1.UpdateOptions{})
		Expect(err).To(HaveOccurred())
	})

	It("attempting to deny a certificate request without the approve permission should error", func() {
		approvedCR := request.DeepCopy()
		apiutil.SetCertificateRequestCondition(approvedCR, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err := saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), approvedCR, metav1.UpdateOptions{})
		Expect(err).To(HaveOccurred())
	})

	//

	It("a service account with the approve permissions for a resource that doesn't exist attempting to approve should error", func() {
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/*", group))

		approvedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(approvedCR, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), approvedCR, metav1.UpdateOptions{})
		Expect(err).To(HaveOccurred())
	})

	It("a service account with the approve permissions for a resource that doesn't exist attempting to deny should error", func() {
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/*", group))

		deniedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(deniedCR, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), deniedCR, metav1.UpdateOptions{})
		Expect(err).To(HaveOccurred())
	})

	//

	It("a service account with the approve permissions for cluster scoped issuers.example.io/* should be able to approve requests", func() {
		crd = createCRD(crdclient, group, "issuers", "Issuer", crdapi.ClusterScoped)
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/*", group))

		approvedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(approvedCR, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), approvedCR, metav1.UpdateOptions{})
		Expect(err).ToNot(HaveOccurred())
	})

	It("a service account with the approve permissions for cluster scoped issuers.example.io/* should be able to deny requests", func() {
		crd = createCRD(crdclient, group, "issuers", "Issuer", crdapi.ClusterScoped)
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/*", group))

		deniedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(deniedCR, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), deniedCR, metav1.UpdateOptions{})
		Expect(err).ToNot(HaveOccurred())
	})

	//

	It("a service account with the approve permissions for cluster scoped issuers.example.io/test-issuer should be able to approve requests", func() {
		crd = createCRD(crdclient, group, "issuers", "Issuer", crdapi.ClusterScoped)
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/test-issuer", group))

		approvedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(approvedCR, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), approvedCR, metav1.UpdateOptions{})
		Expect(err).ToNot(HaveOccurred())
	})

	It("a service account with the approve permissions for cluster scoped issuers.example.io/<namespace>.test-issuer should not be able to approve requests", func() {
		crd = createCRD(crdclient, group, "issuers", "Issuer", crdapi.ClusterScoped)
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/%s.test-issuer", f.Namespace.Name, group))

		approvedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(approvedCR, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), approvedCR, metav1.UpdateOptions{})
		Expect(err).To(HaveOccurred())
	})

	It("a service account with the approve permissions for namespaced scoped issuers.example.io/<namespace>.test-issuer should be able to approve requests", func() {
		crd = createCRD(crdclient, group, "issuers", "Issuer", crdapi.NamespaceScoped)
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/%s.test-issuer", group, f.Namespace.Name))

		approvedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(approvedCR, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), approvedCR, metav1.UpdateOptions{})
		Expect(err).ToNot(HaveOccurred())
	})

	It("a service account with the approve permissions for namespaced scoped issuers.example.io/test-issuer should not be able to approve requests", func() {
		crd = createCRD(crdclient, group, "issuers", "Issuer", crdapi.NamespaceScoped)
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/test-issuer", group))

		approvedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(approvedCR, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), approvedCR, metav1.UpdateOptions{})
		Expect(err).To(HaveOccurred())
	})

	//

	It("a service account with the approve permissions for cluster scoped issuers.example.io/test-issuer should be able to deny requests", func() {
		crd = createCRD(crdclient, group, "issuers", "Issuer", crdapi.ClusterScoped)
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/test-issuer", group))

		deniedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(deniedCR, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), deniedCR, metav1.UpdateOptions{})
		Expect(err).ToNot(HaveOccurred())
	})

	It("a service account with the approve permissions for cluster scoped issuers.example.io/<namespace>.test-issuer should not be able to deny requests", func() {
		crd = createCRD(crdclient, group, "issuers", "Issuer", crdapi.ClusterScoped)
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/%s.test-issuer", f.Namespace.Name, group))

		deniedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(deniedCR, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), deniedCR, metav1.UpdateOptions{})
		Expect(err).To(HaveOccurred())
	})

	It("a service account with the approve permissions for namespaced scoped issuers.example.io/<namespace>.test-issuer should be able to deny requests", func() {
		crd = createCRD(crdclient, group, "issuers", "Issuer", crdapi.NamespaceScoped)
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/%s.test-issuer", group, f.Namespace.Name))

		deniedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(deniedCR, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), deniedCR, metav1.UpdateOptions{})
		Expect(err).ToNot(HaveOccurred())
	})

	It("a service account with the approve permissions for namespaced scoped issuers.example.io/test-issuer should not be able to denied requests", func() {
		crd = createCRD(crdclient, group, "issuers", "Issuer", crdapi.NamespaceScoped)
		bindServiceAccountToApprove(f, sa, fmt.Sprintf("issuers.%s/test-issuer", group))

		deniedCR, err := f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Get(context.TODO(), request.Name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		apiutil.SetCertificateRequestCondition(deniedCR, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "cert-manager.io", "e2e")
		_, err = saclient.CertmanagerV1().CertificateRequests(f.Namespace.Name).UpdateStatus(context.TODO(), deniedCR, metav1.UpdateOptions{})
		Expect(err).To(HaveOccurred())
	})

})

func createCRD(crdclient crdclientset.Interface, group, plural, kind string, scope crdapi.ResourceScope) *crdapi.CustomResourceDefinition {
	crd, err := crdclient.ApiextensionsV1().CustomResourceDefinitions().Create(context.TODO(), &crdapi.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s.%s", plural, group),
		},
		Spec: crdapi.CustomResourceDefinitionSpec{
			Group: group,
			Names: crdapi.CustomResourceDefinitionNames{
				Kind:   kind,
				Plural: plural,
			},
			Versions: []crdapi.CustomResourceDefinitionVersion{
				{
					Name:    "v1alpha1",
					Served:  true,
					Storage: true,
					Schema: &crdapi.CustomResourceValidation{
						OpenAPIV3Schema: &crdapi.JSONSchemaProps{
							Type:       "object",
							Properties: map[string]crdapi.JSONSchemaProps{},
						},
					},
				},
			},
			Scope: scope,
		},
	}, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())
	return crd
}

func bindServiceAccountToApprove(f *framework.Framework, sa *corev1.ServiceAccount, resourceName string) {
	clusterrole, err := f.KubeClientSet.RbacV1().ClusterRoles().Create(context.TODO(), &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "certificaterequest-approver-",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{"cert-manager.io"},
				Resources:     []string{"signers"},
				Verbs:         []string{"approve"},
				ResourceNames: []string{resourceName},
			},
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	_, err = f.KubeClientSet.RbacV1().ClusterRoleBindings().Create(context.TODO(), &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "certificaterequest-approver-",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: sa.Namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterrole.Name,
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}
