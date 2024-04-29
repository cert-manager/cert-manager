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

package framework

import (
	"context"
	"fmt"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/component-base/featuregate"

	. "github.com/cert-manager/cert-manager/e2e-tests/framework/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func nowStamp() string {
	return time.Now().Format(time.StampMilli)
}

func Failf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	Logf(msg)
	Fail(nowStamp()+": "+msg, 1)
}

func Skipf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	Logf("INFO", msg)
	Skip(nowStamp() + ": " + msg)
}

func RequireFeatureGate(f *Framework, featureSet featuregate.FeatureGate, gate featuregate.Feature) {
	if !featureSet.Enabled(gate) {
		Skipf("feature gate %q is not enabled, skipping test", gate)
	}
}

// TODO: move this function into a different package
func RbacClusterRoleHasAccessToResource(f *Framework, clusterRole string, verb string, resource string) bool {
	By("Creating a service account")
	viewServiceAccount := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "rbac-test-",
		},
	}
	serviceAccountClient := f.KubeClientSet.CoreV1().ServiceAccounts(f.Namespace.Name)
	serviceAccount, err := serviceAccountClient.Create(context.TODO(), viewServiceAccount, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	viewServiceAccountName := serviceAccount.Name

	By("Creating ClusterRoleBinding to view " + clusterRole + " clusterRole")
	viewRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: viewServiceAccountName + "-rb-",
		},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: viewServiceAccountName, Namespace: f.Namespace.Name},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRole,
		},
	}
	roleBindingClient := f.KubeClientSet.RbacV1().ClusterRoleBindings()
	_, err = roleBindingClient.Create(context.TODO(), viewRoleBinding, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	By("Sleeping for a second.")
	// to allow RBAC to propagate
	time.Sleep(time.Second)

	By("Impersonating the Service Account")
	impersonateConfig := f.KubeClientConfig
	impersonateConfig.Impersonate.UserName = "system:serviceaccount:" + f.Namespace.Name + ":" + viewServiceAccountName
	impersonateClient, err := kubernetes.NewForConfig(impersonateConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Submitting a self subject access review")
	sarClient := impersonateClient.AuthorizationV1().SelfSubjectAccessReviews()
	sar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: f.Namespace.Name,
				Verb:      verb,
				Group:     "cert-manager.io",
				Resource:  resource,
			},
		},
	}
	response, err := sarClient.Create(context.TODO(), sar, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	return response.Status.Allowed
}
