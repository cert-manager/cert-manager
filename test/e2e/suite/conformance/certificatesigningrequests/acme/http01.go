/*
Copyright 2021 The cert-manager Authors.

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

package acme

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
)

func (a *acme) createHTTP01Issuer(f *framework.Framework) string {
	a.ensureEABSecret(f, "")

	By("Creating an ACME HTTP01 Issuer")
	issuer := &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "acme-issuer-http01-",
		},
		Spec: a.createHTTP01IssuerSpec(f.Config.Addons.ACMEServer.URL),
	}

	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create acme HTTP01 issuer")

	return fmt.Sprintf("issuers.cert-manager.io/%s.%s", issuer.Namespace, issuer.Name)
}

func (a *acme) createHTTP01ClusterIssuer(f *framework.Framework) string {
	a.ensureEABSecret(f, f.Config.Addons.CertManager.ClusterResourceNamespace)

	By("Creating an ACME HTTP01 ClusterIssuer")
	issuer := &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "acme-cluster-issuer-http01-",
		},
		Spec: a.createHTTP01IssuerSpec(f.Config.Addons.ACMEServer.URL),
	}

	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), issuer, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create acme HTTP01 cluster issuer")

	return fmt.Sprintf("clusterissuers.cert-manager.io/%s", issuer.Name)
}

func (a *acme) createHTTP01IssuerSpec(serverURL string) cmapi.IssuerSpec {
	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			ACME: &cmacme.ACMEIssuer{
				Server:        serverURL,
				SkipTLSVerify: true,
				PrivateKey: cmmeta.SecretKeySelector{
					LocalObjectReference: cmmeta.LocalObjectReference{
						Name: "acme-private-key-http01",
					},
				},
				ExternalAccountBinding: a.eab,
				Solvers: []cmacme.ACMEChallengeSolver{
					{
						HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
							// Not setting the Class or Name field will cause cert-manager to create
							// new ingress resources that do not specify a class to solve challenges,
							// which means all Ingress controllers should act on the ingresses.
							Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
						},
					},
				},
			},
		},
	}
}
