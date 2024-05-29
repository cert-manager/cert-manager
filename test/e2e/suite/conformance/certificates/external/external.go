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

package external

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	crtclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/e2e-tests/suite/conformance/certificates"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	sampleExternalIssuerNamespace = "sample-external-issuer-system"
)

var _ = framework.ConformanceDescribe("Certificates", func() {
	unsupportedFeatures := featureset.NewFeatureSet(
		featureset.DurationFeature,
		featureset.KeyUsagesFeature,
		featureset.SaveCAToSecret,
		featureset.Ed25519FeatureSet,
		featureset.IssueCAFeature,
		featureset.LiteralSubjectFeature,
		featureset.OtherNamesFeature,
	)

	issuerBuilder := newIssuerBuilder("Issuer")
	(&certificates.Suite{
		Name:                "External Issuer",
		CreateIssuerFunc:    issuerBuilder.create,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()

	clusterIssuerBuilder := newIssuerBuilder("ClusterIssuer")
	(&certificates.Suite{
		Name:                "External ClusterIssuer",
		CreateIssuerFunc:    clusterIssuerBuilder.create,
		DeleteIssuerFunc:    clusterIssuerBuilder.delete,
		UnsupportedFeatures: unsupportedFeatures,
	}).Define()
})

type issuerBuilder struct {
	clusterResourceNamespace string
	prototype                *unstructured.Unstructured
}

func newIssuerBuilder(issuerKind string) *issuerBuilder {
	return &issuerBuilder{
		clusterResourceNamespace: sampleExternalIssuerNamespace,
		prototype: &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "sample-issuer.example.com/v1alpha1",
				"kind":       issuerKind,
				"spec": map[string]interface{}{
					"url": "http://sample-issuer.example.com/api/v1",
				},
			},
		},
	}
}

func (o *issuerBuilder) nameForTestObject(f *framework.Framework, suffix string) types.NamespacedName {
	namespace := f.Namespace.Name
	if o.prototype.GetKind() == "ClusterIssuer" {
		namespace = o.clusterResourceNamespace
	}
	return types.NamespacedName{
		Name:      fmt.Sprintf("%s-%s", f.Namespace.Name, suffix),
		Namespace: namespace,
	}
}

func (o *issuerBuilder) secretAndIssuerForTest(f *framework.Framework) (*corev1.Secret, *unstructured.Unstructured, error) {
	secretName := o.nameForTestObject(f, "credentials")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName.Name,
			Namespace: secretName.Namespace,
		},
		StringData: map[string]string{},
	}

	issuerName := o.nameForTestObject(f, "issuer")
	issuer := o.prototype.DeepCopy()
	issuer.SetName(issuerName.Name)
	issuer.SetNamespace(issuerName.Namespace)
	err := unstructured.SetNestedField(issuer.Object, secret.Name, "spec", "authSecretName")

	return secret, issuer, err
}

func (o *issuerBuilder) create(ctx context.Context, f *framework.Framework) cmmeta.ObjectReference {
	By("Creating an Issuer")
	secret, issuer, err := o.secretAndIssuerForTest(f)
	Expect(err).NotTo(HaveOccurred(), "failed to initialise test objects")

	crt, err := crtclient.New(f.KubeClientConfig, crtclient.Options{})
	Expect(err).NotTo(HaveOccurred(), "failed to create controller-runtime client")

	err = crt.Create(ctx, secret)
	Expect(err).NotTo(HaveOccurred(), "failed to create secret")

	err = crt.Create(ctx, issuer)
	Expect(err).NotTo(HaveOccurred(), "failed to create issuer")

	return cmmeta.ObjectReference{
		Group: issuer.GroupVersionKind().Group,
		Kind:  issuer.GroupVersionKind().Kind,
		Name:  issuer.GetName(),
	}
}

func (o *issuerBuilder) delete(ctx context.Context, f *framework.Framework, _ cmmeta.ObjectReference) {
	By("Deleting the issuer")
	crt, err := crtclient.New(f.KubeClientConfig, crtclient.Options{})
	Expect(err).NotTo(HaveOccurred(), "failed to create controller-runtime client")

	secret, issuer, err := o.secretAndIssuerForTest(f)
	Expect(err).NotTo(HaveOccurred(), "failed to initialise test objects")

	err = crt.Delete(ctx, issuer)
	Expect(err).NotTo(HaveOccurred(), "failed to delete issuer")

	err = crt.Delete(ctx, secret)
	Expect(err).NotTo(HaveOccurred(), "failed to delete secret")
}
