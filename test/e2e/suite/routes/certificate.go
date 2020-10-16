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

package routes

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/unit/gen"
	routev1 "github.com/openshift/api/route/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = framework.CertManagerDescribe("route binding", func() {
	f := framework.NewDefaultFramework("create-ca-certificate")
	h := f.Helper()

	// issuerName := "test-ca-issuer"
	issuerSecretName := "ca-issuer-signing-keypair"
	routeName := "test-ca-route"
	certificateSecretName := "test-ca-certificate"
	certKeyValue := "cert-key"
	certValue := "cert-value"
	caValue := "ca-value"

	AfterEach(func() {
		By("Cleaning up")
		f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Delete(context.TODO(), issuerSecretName, metav1.DeleteOptions{})
		f.RouteV1ClientSet.RouteV1().Routes(f.Namespace.Name).Delete(context.TODO(), routeName, metav1.DeleteOptions{})
	})

	Context("when the route has an annotation", func() {
		It("should attach provided secret to TLS edge/reencrypt route", func() {
			routeClient := f.RouteV1ClientSet.RouteV1().Routes(f.Namespace.Name)
			secretClient := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name)

			By("Creating a test secret to annotate route with")
			secretData := make(map[string][]byte)
			secretData["tls.key"] = []byte(certKeyValue)
			secretData["tls.crt"] = []byte(certValue)

			_, err := secretClient.Create(context.TODO(), gen.Secret(certificateSecretName, gen.SetSecretData(secretData), gen.SetSecretNamespace(f.Namespace.Name)), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Creating a Route with Annotations")
			routeAnnotations := make(map[string]string)
			routeAnnotations["routes.cert-manager.io/certs-from-secret"] = certificateSecretName
			_, err = routeClient.Create(context.TODO(),
				gen.Route(routeName, gen.SetRouteNamespace(f.Namespace.Name),
					gen.AddRouteAnnotations(routeAnnotations),
					gen.SetTLSType(routev1.TLSTerminationEdge),
				), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Verifying the route is valid")
			err = h.WaitRouteValidTLS(f.Namespace.Name, routeName, time.Second*30, certKeyValue, certValue)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should NOT attach provided secret to uneencrypted route", func() {
			routeClient := f.RouteV1ClientSet.RouteV1().Routes(f.Namespace.Name)
			secretClient := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name)

			By("Creating a test secret to annotate route with")
			secretData := make(map[string][]byte)
			secretData["tls.key"] = []byte(certKeyValue)
			secretData["tls.crt"] = []byte(certValue)

			_, err := secretClient.Create(context.TODO(), gen.Secret(certificateSecretName, gen.SetSecretData(secretData), gen.SetSecretNamespace(f.Namespace.Name)), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Creating a Route with Annotations")
			routeAnnotations := make(map[string]string)
			routeAnnotations["routes.cert-manager.io/certs-from-secret"] = certificateSecretName
			_, err = routeClient.Create(context.TODO(),
				gen.Route(routeName, gen.SetRouteNamespace(f.Namespace.Name),
					gen.AddRouteAnnotations(routeAnnotations),
				), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Verifying the route is valid")
			err = h.WaitRouteValidTLS(f.Namespace.Name, routeName, time.Second*30, certKeyValue, certValue)
			Expect(err).NotTo(BeNil())
		})

		It("should attach provided secret to route destination CA", func() {
			routeClient := f.RouteV1ClientSet.RouteV1().Routes(f.Namespace.Name)
			secretClient := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name)

			By("Creating a test secret to annotate route with")
			secretData := make(map[string][]byte)
			secretData["ca.crt"] = []byte(caValue)

			_, err := secretClient.Create(context.TODO(), gen.Secret(certificateSecretName, gen.SetSecretData(secretData), gen.SetSecretNamespace(f.Namespace.Name)), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Creating a Route with Annotations")
			routeAnnotations := make(map[string]string)
			routeAnnotations["routes.cert-manager.io/destinationCA-from-secret"] = certificateSecretName
			_, err = routeClient.Create(context.TODO(),
				gen.Route(routeName, gen.SetRouteNamespace(f.Namespace.Name),
					gen.AddRouteAnnotations(routeAnnotations),
					gen.SetTLSType(routev1.TLSTerminationEdge),
				), metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			By("Verifying the route is valid")
			err = h.WaitRouteValidCA(f.Namespace.Name, routeName, time.Second*30, caValue)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
