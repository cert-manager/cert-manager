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

package certificaterequests

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	testutil "github.com/jetstack/cert-manager/test/e2e/framework/util"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

// Check that the identity fields on CertificateRequests are populated
// correctly, and they cannot be modified.
var _ = framework.CertManagerDescribe("Identity CertificateRequests", func() {
	f := framework.NewDefaultFramework("identity-certificaterequests")

	It("should appropriately create set identity of CertificateRequests, and reject changes", func() {
		var (
			adminUsername = "kubernetes-admin"
			adminGroups   = []string{"system:masters", "system:authenticated"}
		)
		csr, _, err := gen.CSR(x509.RSA)
		Expect(err).NotTo(HaveOccurred())

		cr := gen.CertificateRequest("test-v1",
			gen.SetCertificateRequestNamespace(f.Namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name: "issuer",
			}),
		)

		By("Creating CertificateRequest")
		cr, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Create(context.TODO(), cr, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Ensure identity fields are set")
		if cr.Spec.Username != adminUsername {
			Fail(fmt.Sprintf("Unexpected username in CertificateRequest, exp=%s got=%s", adminUsername, cr.Spec.Username))
		}
		if !util.EqualUnsorted(cr.Spec.Groups, adminGroups) {
			Fail(fmt.Sprintf("Unexpected groups in CertificateRequest, exp=%s got=%s", adminGroups, cr.Spec.Groups))
		}

		By("Should error when attempting to update identity fields")
		cr.Spec.Username = "abc"
		cr.Spec.UID = "123"
		cr, err = f.CertManagerClientSet.CertmanagerV1().CertificateRequests(f.Namespace.Name).Update(context.TODO(), cr, metav1.UpdateOptions{})
		Expect(err).To(HaveOccurred())
	})

	It("should populate identity with ServiceAccount if is the requester", func() {
		By("Creating ServiceAccount")
		sa, err := f.KubeClientSet.CoreV1().ServiceAccounts(f.Namespace.Name).Create(context.TODO(), &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-sa",
				Namespace: f.Namespace.Name,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating certificaterequest-creator role")
		role, err := f.KubeClientSet.RbacV1().Roles(f.Namespace.Name).Create(context.TODO(), &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "certificaterequest-creator",
				Namespace: f.Namespace.Name,
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"create"},
					APIGroups: []string{"cert-manager.io"},
					Resources: []string{"certificaterequests"},
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Creating certificaterequest-creator rolebinding for ServiceAccount")
		_, err = f.KubeClientSet.RbacV1().RoleBindings(f.Namespace.Name).Create(context.TODO(), &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "certificaterequest-creator",
				Namespace: f.Namespace.Name,
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

		By("Waiting for service account secret to be created")
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

		client, err := clientset.NewForConfig(kubeConfig)
		Expect(err).NotTo(HaveOccurred())

		csr, _, err := gen.CSR(x509.RSA)
		Expect(err).NotTo(HaveOccurred())

		cr := gen.CertificateRequest("test-v1",
			gen.SetCertificateRequestNamespace(f.Namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name: "issuer",
			}),
		)

		By("Creating CertificateRequest")
		cr, err = client.CertmanagerV1().CertificateRequests(f.Namespace.Name).Create(context.TODO(), cr, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		fmt.Printf("%s %s %s %s", cr.Spec.UID, cr.Spec.Username, cr.Spec.Groups, cr.Spec.Extra)

		expUsername := fmt.Sprintf("system:serviceaccount:%s:%s", f.Namespace.Name, sa.Name)
		expGroups := []string{
			"system:serviceaccounts",
			"system:authenticated",
			fmt.Sprintf("system:serviceaccounts:%s", f.Namespace.Name),
		}
		By("Ensure identity fields are set")
		if cr.Spec.UID != string(sa.UID) {
			Fail(fmt.Sprintf("Unexpected UID in CertificateRequest, exp=%s got=%s", sa.UID, cr.Spec.UID))
		}
		if cr.Spec.Username != expUsername {
			Fail(fmt.Sprintf("Unexpected username in CertificateRequest, exp=%s got=%s", expUsername, cr.Spec.Username))
		}
		if !util.EqualUnsorted(cr.Spec.Groups, expGroups) {
			Fail(fmt.Sprintf("Unexpected groups in CertificateRequest, exp=%s got=%s", expGroups, cr.Spec.Groups))
		}
		if len(cr.Spec.Extra) > 0 {
			Fail(fmt.Sprintf("Unexpected extra in CertificateRequest, exp=nil got=%s", cr.Spec.Groups))
		}
	})
})
