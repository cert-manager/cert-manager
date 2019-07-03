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

package rbac

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/cert-manager/test/e2e/framework"
)

var _ = RBACDescribe("CertificateRequests", func() {
	f := framework.NewDefaultFramework("rbac-certificaterequests")
	resource := "certificaterequests" // this file is related to certificaterequests

	Context("with namespace view access", func() {
		clusterRole := "view"
		It("shouldn't be able to create certificaterequests", func() {
			verb := "create"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeFalse())
		})

		It("shouldn't be able to delete certificaterequests", func() {
			verb := "delete"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeFalse())
		})

		It("shouldn't be able to delete collections of certificaterequests", func() {
			verb := "deletecollection"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeFalse())
		})

		It("shouldn't be able to patch certificaterequests", func() {
			verb := "patch"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeFalse())
		})

		It("shouldn't be able to update certificaterequests", func() {
			verb := "update"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeFalse())
		})

		It("should be able to get certificaterequests", func() {
			verb := "get"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to list certificaterequests", func() {
			verb := "list"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to watch certificaterequests", func() {
			verb := "watch"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})
	})
	Context("with namespace edit access", func() {
		clusterRole := "edit"
		It("should be able to create certificaterequests", func() {
			verb := "create"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to delete certificaterequests", func() {
			verb := "delete"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to delete collections of certificaterequests", func() {
			verb := "deletecollection"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to patch certificaterequests", func() {
			verb := "patch"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to update certificaterequests", func() {
			verb := "update"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to get certificaterequests", func() {
			verb := "get"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to list certificaterequests", func() {
			verb := "list"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to watch certificaterequests", func() {
			verb := "watch"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})
	})

	Context("with namespace admin access", func() {
		clusterRole := "admin"
		It("should be able to create certificaterequests", func() {
			verb := "create"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to delete certificaterequests", func() {
			verb := "delete"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to delete collections of certificaterequests", func() {
			verb := "deletecollection"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to patch certificaterequests", func() {
			verb := "patch"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to update certificaterequests", func() {
			verb := "update"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to get certificaterequests", func() {
			verb := "get"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to list certificaterequests", func() {
			verb := "list"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})

		It("should be able to watch certificaterequests", func() {
			verb := "watch"

			hasAccess := framework.RbacClusterRoleHasAccessToResource(f, clusterRole, verb, resource)
			Expect(hasAccess).Should(BeTrue())
		})
	})
})
