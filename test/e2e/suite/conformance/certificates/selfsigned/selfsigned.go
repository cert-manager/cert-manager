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
	"fmt"
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	valcert "github.com/jetstack/cert-manager/test/e2e/framework/helper/validation/certificates"
	"github.com/jetstack/cert-manager/test/e2e/suite/conformance/certificates"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	(&certificates.Suite{
		Name: "SelfSigned Issuer",
		CreateIssuerFunc: createSelfSignedIssuer(
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
		),
		ExtraValidations: []valcert.ValidationFunc{valcert.ExpectValidMaxPathLen(-1, false)},
	}).Define()

	(&certificates.Suite{
		Name: "SelfSigned ClusterIssuer",
		CreateIssuerFunc: createSelfSignedClusterIssuer(
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
		),
		DeleteIssuerFunc: deleteSelfSignedClusterIssuer,
		ExtraValidations: []valcert.ValidationFunc{valcert.ExpectValidMaxPathLen(-1, false)},
	}).Define()

	rand.Seed(time.Now().UnixNano())
	pathLen := rand.Intn(5)

	(&certificates.Suite{
		Name: fmt.Sprintf("SelfSigned PathLen=%d Issuer", pathLen),
		CreateIssuerFunc: createSelfSignedIssuer(
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{
				IsCA:    pointer.Bool(true),
				PathLen: &pathLen,
			}),
		),
		ExtraValidations: []valcert.ValidationFunc{valcert.ExpectValidMaxPathLen(pathLen, pathLen == 0), valcert.ExpectCARootCertificate},
	}).Define()

	(&certificates.Suite{
		Name: fmt.Sprintf("SelfSigned PathLen=%d ClusterIssuer", pathLen),
		CreateIssuerFunc: createSelfSignedClusterIssuer(
			gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{
				IsCA:    pointer.Bool(true),
				PathLen: &pathLen,
			}),
		),
		DeleteIssuerFunc: deleteSelfSignedClusterIssuer,
		ExtraValidations: []valcert.ValidationFunc{valcert.ExpectValidMaxPathLen(pathLen, pathLen == 0), valcert.ExpectCARootCertificate},
	}).Define()
})

func createSelfSignedIssuer(mods ...gen.IssuerModifier) func(f *framework.Framework) cmmeta.ObjectReference {
	return func(f *framework.Framework) cmmeta.ObjectReference {
		By("Creating a SelfSigned Issuer")
		issuer := gen.IssuerWithRandomName("selfsigned-issuer-", mods...)

		issuer, err := f.CertManagerClientSet.CertmanagerV1().Issuers(f.Namespace.Name).Create(context.TODO(), issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to create self signed issuer")

		return cmmeta.ObjectReference{
			Group: cmapi.SchemeGroupVersion.Group,
			Kind:  cmapi.IssuerKind,
			Name:  issuer.Name,
		}
	}
}

func createSelfSignedClusterIssuer(mods ...gen.IssuerModifier) func(f *framework.Framework) cmmeta.ObjectReference {
	return func(f *framework.Framework) cmmeta.ObjectReference {
		By("Creating a SelfSigned Issuer")
		issuer := gen.ClusterIssuerWithRandomName("selfsigned-cluster-issuer-", mods...)

		issuer, err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Create(context.TODO(), issuer, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to create self signed issuer")

		return cmmeta.ObjectReference{
			Group: cmapi.SchemeGroupVersion.Group,
			Kind:  cmapi.IssuerKind,
			Name:  issuer.Name,
		}
	}
}

func deleteSelfSignedClusterIssuer(f *framework.Framework, issuer cmmeta.ObjectReference) {
	err := f.CertManagerClientSet.CertmanagerV1().ClusterIssuers().Delete(context.TODO(), issuer.Name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
}
