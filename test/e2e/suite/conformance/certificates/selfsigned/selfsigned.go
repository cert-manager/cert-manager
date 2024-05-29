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

package selfsigned

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/suite/conformance/certificates"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	(&certificates.Suite{
		Name:             "SelfSigned Issuer",
		CreateIssuerFunc: createSelfSignedIssuer,
	}).Define()

	(&certificates.Suite{
		Name:             "SelfSigned ClusterIssuer",
		CreateIssuerFunc: createSelfSignedClusterIssuer,
		DeleteIssuerFunc: deleteSelfSignedClusterIssuer,
	}).Define()
})

func createSelfSignedIssuer(ctx context.Context, f *framework.Framework) cmmeta.ObjectReference {
	By("Creating a SelfSigned Issuer")

	issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(ctx, &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "selfsigned-issuer-",
		},
		Spec: createSelfSignedIssuerSpec(),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create self signed issuer")

	// wait for issuer to be ready
	By("Waiting for Self Signed Issuer to be Ready")
	issuer, err = f.Helper().WaitIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.IssuerKind,
		Name:  issuer.Name,
	}
}

func deleteSelfSignedClusterIssuer(ctx context.Context, f *framework.Framework, issuer cmmeta.ObjectReference) {
	err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(ctx, issuer.Name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func createSelfSignedClusterIssuer(ctx context.Context, f *framework.Framework) cmmeta.ObjectReference {
	By("Creating a SelfSigned ClusterIssuer")

	issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(ctx, &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "selfsigned-cluster-issuer-",
		},
		Spec: createSelfSignedIssuerSpec(),
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create self signed issuer")

	// wait for issuer to be ready
	By("Waiting for Self Signed Cluster Issuer to be Ready")
	issuer, err = f.Helper().WaitClusterIssuerReady(ctx, issuer, time.Minute*5)
	Expect(err).ToNot(HaveOccurred())

	return cmmeta.ObjectReference{
		Group: cmapi.SchemeGroupVersion.Group,
		Kind:  cmapi.ClusterIssuerKind,
		Name:  issuer.Name,
	}
}

func createSelfSignedIssuerSpec() cmapi.IssuerSpec {
	return cmapi.IssuerSpec{
		IssuerConfig: cmapi.IssuerConfig{
			SelfSigned: &cmapi.SelfSignedIssuer{},
		},
	}
}
