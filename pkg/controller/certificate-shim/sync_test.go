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

package shimhelper

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_hasShimAnnotation(t *testing.T) {
	type testT struct {
		Annot map[string]string
		Want  bool
	}

	t.Run("ingress", func(t *testing.T) {
		tests := []testT{
			{Annot: map[string]string{"cert-manager.io/issuer": ""}, Want: true},
			{Annot: map[string]string{"cert-manager.io/cluster-issuer": ""}, Want: true},
			{Annot: map[string]string{"kubernetes.io/tls-acme": "true"}, Want: true},
			{Annot: map[string]string{"kubernetes.io/tls-acme": "false"}, Want: false},
			{Annot: map[string]string{"kubernetes.io/tls-acme": ""}, Want: false},
			{Annot: nil, Want: false},
		}
		for _, test := range tests {
			shouldSyncIngress := hasShimAnnotation(buildIngress("", "", test.Annot), []string{"kubernetes.io/tls-acme"})
			if shouldSyncIngress != test.Want {
				t.Errorf("Expected shouldSyncIngress=%v for annotations %#v", test.Want, test.Annot)
			}
			shouldSyncGateway := hasShimAnnotation(buildGateway("", "", test.Annot), []string{"kubernetes.io/tls-acme"})
			if shouldSyncGateway != test.Want {
				t.Errorf("Expected shouldSyncGateway=%v for annotations %#v", test.Want, test.Annot)
			}
		}
	})
}

func TestSync(t *testing.T) {
	clusterIssuer := gen.ClusterIssuer("issuer-name")
	acmeIssuerNewFormat := gen.Issuer("issuer-name",
		gen.SetIssuerACME(cmacme.ACMEIssuer{}))
	acmeIssuer := gen.Issuer("issuer-name",
		gen.SetIssuerACME(cmacme.ACMEIssuer{}))
	acmeClusterIssuer := gen.ClusterIssuer("issuer-name",
		gen.SetIssuerACME(cmacme.ACMEIssuer{}))
	type testT struct {
		Name                string
		IngressLike         metav1.Object
		Issuer              cmapi.GenericIssuer
		IssuerLister        []runtime.Object
		ClusterIssuerLister []runtime.Object
		CertificateLister   []runtime.Object
		DefaultIssuerName   string
		DefaultIssuerKind   string
		DefaultIssuerGroup  string
		Err                 bool
		ExpectedCreate      []*cmapi.Certificate
		ExpectedUpdate      []*cmapi.Certificate
		ExpectedDelete      []*cmapi.Certificate
		ExpectedEvents      []string
	}
	testIngressShim := []testT{
		{
			Name:   "return a single Certificate for an ingress with a single valid TLS entry and common-name annotation",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.CommonNameAnnotationKey:               "my-cn",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						CommonName: "my-cn",
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single Certificate for an ingress with dnsNames and ipv4 addresses",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.CommonNameAnnotationKey:               "my-cn",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com", "10.112.234.34", "1.1.1.1"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:    []string{"example.com", "www.example.com"},
						IPAddresses: []string{"10.112.234.34", "1.1.1.1"},
						CommonName:  "my-cn",
						SecretName:  "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single Certificate for an ingress with dnsNames and ipv6 addresses",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.CommonNameAnnotationKey:               "my-cn",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com", "2a00:1450:4009:819::aaaa", "2a00:1450:4009:819::eeee"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:    []string{"example.com", "www.example.com"},
						IPAddresses: []string{"2a00:1450:4009:819::aaaa", "2a00:1450:4009:819::eeee"},
						CommonName:  "my-cn",
						SecretName:  "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single Certificate for an ingress with dnsNames and ipv4 and ipv6 addresses",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.CommonNameAnnotationKey:               "my-cn",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com", "1.1.1.1", "2a00:1450:4009:819::eeee"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:    []string{"example.com", "www.example.com"},
						IPAddresses: []string{"1.1.1.1", "2a00:1450:4009:819::eeee"},
						CommonName:  "my-cn",
						SecretName:  "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations using edit-in-place",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmacme.IngressEditInPlaceAnnotationKey:      "true",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						Annotations: map[string]string{
							cmacme.ACMECertificateHTTP01IngressNameOverride: "ingress-name",
							cmapi.IssueTemporaryCertificateAnnotation:       "true",
						},
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "create a Certificate with the HTTP01 name override if the given ingress uses http01 annotations",
			Issuer: gen.Issuer(acmeIssuer.Name),
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmacme.IngressEditInPlaceAnnotationKey:      "true",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						Annotations: map[string]string{
							cmacme.ACMECertificateHTTP01IngressNameOverride: "ingress-name",
							cmapi.IssueTemporaryCertificateAnnotation:       "true",
						},
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations with no ingress class set",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations with a custom ingress class",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressClassAnnotationKey:             "nginx-ing",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations with a certificate ingress class",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey:            "issuer-name",
						cmapi.IngressACMEIssuerHTTP01IngressClassAnnotationKey: "cert-ing",
						cmapi.IngressClassAnnotationKey:                        "nginx-ing",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
						Annotations: map[string]string{
							cmacme.ACMECertificateHTTP01IngressClassOverride: "cert-ing",
						},
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and valid secret template annotation",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressSecretTemplate:                 `{ "annotations": { "example-annotation" : "dummy-value" }, "labels": { "example-label" : "dummy-value" } }`,
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						SecretTemplate: &cmapi.CertificateSecretTemplate{
							Annotations: map[string]string{
								"example-annotation": "dummy-value",
							},
							Labels: map[string]string{
								"example-label": "dummy-value",
							},
						},
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "secret template annotation should not allow cert-manager.io/ annotations",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressSecretTemplate:                 `{ "annotations": { "cert-manager.io/disallowed-annotation" : "dummy-value" } }`,
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			Err: true,
		},
		{
			Name:   "secret template annotation should not allow unknown fields",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressSecretTemplate:                 `{ "unknown-field": "true" }`,
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			Err: true,
		},
		{
			Name:   "edit-in-place set to false should not trigger editing the ingress in-place",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressClassAnnotationKey:             "nginx-ing",
						cmacme.IngressEditInPlaceAnnotationKey:      "false",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single DNS01 Certificate for an ingress with a single valid TLS entry",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:                "should return a basic certificate when no provider specific config is provided",
			Issuer:              clusterIssuer,
			DefaultIssuerName:   "issuer-name",
			DefaultIssuerKind:   "ClusterIssuer",
			DefaultIssuerGroup:  "cert-manager.io",
			ClusterIssuerLister: []runtime.Object{clusterIssuer},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						"kubernetes.io/tls-acme": "true",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ExpectedEvents: []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "issuer-name",
							Kind:  "ClusterIssuer",
							Group: "cert-manager.io",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should skip an invalid TLS entry (no TLS hosts specified)",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			ExpectedEvents: []string{
				`Warning BadConfig Skipped a TLS block: spec.tls[0].hosts: Required value`,
				`Normal CreateCertificate Successfully created Certificate "example-com-tls"`,
			},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							SecretName: "example-com-tls-invalid",
						},
						{
							SecretName: "example-com-tls",
							Hosts:      []string{"example.com", "www.example.com"},
						},
					},
				},
			},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						Usages:     cmapi.DefaultKeyUsages(),
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
					},
				},
			},
		},

		{
			Name:         "should skip an invalid TLS entry (no TLS secret name specified)",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			ExpectedEvents: []string{
				`Warning BadConfig Skipped a TLS block: spec.tls[0].secretName: Required value`,
				`Normal CreateCertificate Successfully created Certificate "example-com-tls"`,
			},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts: []string{"example.com"},
						},
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						Usages:     cmapi.DefaultKeyUsages(),
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
					},
				},
			},
		},
		{
			Name: "should error if the specified issuer is not found",
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "invalid-issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
			},
		},
		{
			Name:         "should not return any certificates if a correct Certificate already exists",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "existing-crt",
						},
					},
				},
			},
			DefaultIssuerKind:  "Issuer",
			DefaultIssuerGroup: "cert-manager.io",
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "issuer-name",
							Kind:  "Issuer",
							Group: "cert-manager.io",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should update a certificate if an incorrect Certificate exists",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "existing-crt",
						},
					},
				},
			},
			CertificateLister: []runtime.Object{
				buildCertificate("existing-crt",
					gen.DefaultTestNamespace,
					buildIngressOwnerReferences("ingress-name"),
				),
			},
			DefaultIssuerKind: "Issuer",
			ExpectedEvents:    []string{`Normal UpdateCertificate Successfully updated Certificate "existing-crt"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should update an existing Certificate resource with new labels if they do not match those specified on the IngressLike",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuerNewFormat},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "cert-secret-name",
						},
					},
				},
			},
			DefaultIssuerKind: "Issuer",
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cert-secret-name",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"a-different-value": "should be removed",
						},
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "cert-secret-name"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cert-secret-name",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should update an existing Certificate resource with different revision limit if it does not match specified on the IngressLike",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuerNewFormat},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey:    "issuer-name",
						cmapi.RevisionHistoryLimitAnnotationKey: "1",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "cert-secret-name",
						},
					},
				},
			},
			DefaultIssuerKind: "Issuer",
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-secret-name",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages:               cmapi.DefaultKeyUsages(),
						RevisionHistoryLimit: ptr.To(int32(7)),
					},
				},
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "cert-secret-name"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-secret-name",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages:               cmapi.DefaultKeyUsages(),
						RevisionHistoryLimit: ptr.To(int32(1)),
					},
				},
			},
		},
		{
			Name:         "should update an existing Certificate resource with different rsa private key size if it does not match specified on the IngressLike",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuerNewFormat},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey:   "issuer-name",
						cmapi.PrivateKeyAlgorithmAnnotationKey: "RSA",
						cmapi.PrivateKeySizeAnnotationKey:      "4096",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "cert-secret-name",
						},
					},
				},
			},
			DefaultIssuerKind: "Issuer",
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-secret-name",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
						PrivateKey: &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.RSAKeyAlgorithm,
							Size:      2048,
						},
					},
				},
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "cert-secret-name"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-secret-name",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
						PrivateKey: &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.RSAKeyAlgorithm,
							Size:      4096,
						},
					},
				},
			},
		},
		{
			Name:         "should update an existing Certificate resource with different ecdsa private key size if it does not match specified on the IngressLike",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuerNewFormat},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey:   "issuer-name",
						cmapi.PrivateKeyAlgorithmAnnotationKey: "ECDSA",
						cmapi.PrivateKeySizeAnnotationKey:      "384",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "cert-secret-name",
						},
					},
				},
			},
			DefaultIssuerKind: "Issuer",
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-secret-name",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
						PrivateKey: &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.ECDSAKeyAlgorithm,
							Size:      256,
						},
					},
				},
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "cert-secret-name"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-secret-name",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
						PrivateKey: &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.ECDSAKeyAlgorithm,
							Size:      384,
						},
					},
				},
			},
		},
		{
			Name:         "should update an existing Certificate resource with different private key encoding if it does not match specified on the IngressLike",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuerNewFormat},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey:   "issuer-name",
						cmapi.PrivateKeyAlgorithmAnnotationKey: "ECDSA",
						cmapi.PrivateKeyEncodingAnnotationKey:  "PKCS8",
						cmapi.PrivateKeySizeAnnotationKey:      "384",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "cert-secret-name",
						},
					},
				},
			},
			DefaultIssuerKind: "Issuer",
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-secret-name",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
						PrivateKey: &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.ECDSAKeyAlgorithm,
							Size:      384,
						},
					},
				},
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "cert-secret-name"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-secret-name",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
						PrivateKey: &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.ECDSAKeyAlgorithm,
							Encoding:  cmapi.PKCS8,
							Size:      384,
						},
					},
				},
			},
		},
		{
			Name:         "should update an existing Certificate resource with different private key rotation policy if it does not match specified on the IngressLike",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuerNewFormat},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey:        "issuer-name",
						cmapi.PrivateKeyAlgorithmAnnotationKey:      "ECDSA",
						cmapi.PrivateKeyEncodingAnnotationKey:       "PKCS1",
						cmapi.PrivateKeySizeAnnotationKey:           "384",
						cmapi.PrivateKeyRotationPolicyAnnotationKey: "Always",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "cert-secret-name",
						},
					},
				},
			},
			DefaultIssuerKind: "Issuer",
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-secret-name",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
						PrivateKey: &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.ECDSAKeyAlgorithm,
							Size:      384,
						},
					},
				},
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "cert-secret-name"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-secret-name",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
						PrivateKey: &cmapi.CertificatePrivateKey{
							Algorithm:      cmapi.ECDSAKeyAlgorithm,
							Encoding:       cmapi.PKCS1,
							Size:           384,
							RotationPolicy: cmapi.RotationPolicyAlways,
						},
					},
				},
			},
		},
		{
			Name:         "should not update certificate if it does not belong to any ingress",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressClassAnnotationKey:      "toot-ing",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "existing-crt",
						},
					},
				},
			},
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: []metav1.OwnerReference{},
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should not update certificate if it does not belong to the ingress",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressClassAnnotationKey:      "toot-ing",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "existing-crt",
						},
					},
				},
			},
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("not-ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should delete a Certificate if its SecretName is not present in the ingress",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
			},
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
			ExpectedEvents: []string{`Normal DeleteCertificate Successfully deleted unrequired Certificate "existing-crt"`},
			ExpectedDelete: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
					},
				},
			},
		},
		{
			Name:         "should update a Certificate if is contains a Common Name that is not defined on the ingress annotations",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IssuerKindAnnotationKey:        "Issuer",
						cmapi.IssuerGroupAnnotationKey:       "cert-manager.io",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						CommonName: "example-common-name",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "issuer-name",
							Kind:  "Issuer",
							Group: "cert-manager.io",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "example-com-tls"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "issuer-name",
							Kind:  "Issuer",
							Group: "cert-manager.io",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "if an ingress contains multiple tls entries that specify the same secretName, an error should be logged and no action taken",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			ExpectedEvents: []string{
				`Warning BadConfig spec.tls[0].secretName: Invalid value: "example-com-tls": this secret name must only appear in a single TLS entry but is also used in spec.tls[1].secretName`,
			},
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IssuerKindAnnotationKey:        "Issuer",
						cmapi.IssuerGroupAnnotationKey:       "cert-manager.io",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "example-com-tls",
						},
						{
							Hosts:      []string{"notexample.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
		},
		{
			Name:   "Failure to translateIngressAnnotations",
			Issuer: acmeIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey:        "issuer-name",
						cmapi.IssuerKindAnnotationKey:               "Issuer",
						cmapi.IssuerGroupAnnotationKey:              "cert-manager.io",
						cmapi.RenewBeforeAnnotationKey:              "invalid renew before value",
						cmapi.RevisionHistoryLimitAnnotationKey:     "invalid revision history limit value",
						cmapi.PrivateKeyAlgorithmAnnotationKey:      "invalid private key algorithm value",
						cmapi.PrivateKeyEncodingAnnotationKey:       "invalid private key encoding value",
						cmapi.PrivateKeySizeAnnotationKey:           "invalid private key size value",
						cmapi.PrivateKeyRotationPolicyAnnotationKey: "invalid private key rotation policy value",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			Err: true,
		},
		{
			Name:   "return a single Certificate for an ingress with a single valid TLS entry with common-name and keyusage annotation",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.CommonNameAnnotationKey:               "my-cn",
						"cert-manager.io/usages":                    "signing,digital signature,content commitment",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						CommonName: "my-cn",
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: []cmapi.KeyUsage{
							cmapi.UsageSigning,
							cmapi.UsageDigitalSignature,
							cmapi.UsageContentCommitment,
						},
					},
				},
			},
		},
		{
			Name:   "return a single Certificate for an ingress with a single valid TLS entry with common-name and subject street addresses annotation",
			Issuer: acmeClusterIssuer,
			IngressLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.CommonNameAnnotationKey:               "my-cn",
						cmapi.SubjectStreetAddressesAnnotationKey:   `"1725 Slough Avenue, Suite 200, Scranton Business Park"`,
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildIngressOwnerReferences("ingress-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						CommonName: "my-cn",
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Subject: &cmapi.X509Subject{
							StreetAddresses: []string{"1725 Slough Avenue, Suite 200, Scranton Business Park"},
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:                "should not trigger an ingress sync if deleted in foreground",
			Issuer:              clusterIssuer,
			DefaultIssuerName:   "issuer-name",
			DefaultIssuerKind:   "ClusterIssuer",
			DefaultIssuerGroup:  "cert-manager.io",
			ClusterIssuerLister: []runtime.Object{clusterIssuer},
			IngressLike:         buildIngressInDeletion(buildIngress("", "", map[string]string{cmapi.IngressIssuerNameAnnotationKey: ""}), &metav1.Time{}, []string{metav1.FinalizerDeleteDependents}),
		},
	}

	testGatewayShim := []testT{
		{
			Name:   "return a single Certificate for a Gateway with a single valid TLS entry and common-name annotation (HTTPS)",
			Issuer: acmeClusterIssuer,
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.CommonNameAnnotationKey:               "my-cn",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{
						{
							Hostname: ptrHostname("example.com"),
							Port:     443,
							Protocol: gwapi.HTTPSProtocolType,
							TLS: &gwapi.GatewayTLSConfig{
								Mode: ptrMode(gwapi.TLSModeTerminate),
								CertificateRefs: []gwapi.SecretObjectReference{
									{
										Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
										Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
										Name:  "example-com-tls",
									},
								},
							},
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						CommonName: "my-cn",
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single Certificate for a Gateway with a single valid TLS entry and common-name annotation (TLS)",
			Issuer: acmeClusterIssuer,
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.CommonNameAnnotationKey:               "my-cn",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{
						{
							Hostname: ptrHostname("example.com"),
							Port:     443,
							Protocol: gwapi.TLSProtocolType,
							TLS: &gwapi.GatewayTLSConfig{
								Mode: ptrMode(gwapi.TLSModeTerminate),
								CertificateRefs: []gwapi.SecretObjectReference{
									{
										Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
										Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
										Name:  "example-com-tls",
									},
								},
							},
						},
					},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						CommonName: "my-cn",
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for a Gateway with a single valid TLS entry and HTTP01 annotations using edit-in-place",
			Issuer: acmeClusterIssuer,
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmacme.IngressEditInPlaceAnnotationKey:      "true",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						Annotations: map[string]string{
							cmacme.ACMECertificateHTTP01IngressNameOverride: "gateway-name",
							cmapi.IssueTemporaryCertificateAnnotation:       "true",
						},
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "create a Certificate with the HTTP01 name override if the given Gateway uses http01 annotations",
			Issuer: gen.Issuer(acmeIssuer.Name),
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmacme.IngressEditInPlaceAnnotationKey:      "true",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						Annotations: map[string]string{
							cmacme.ACMECertificateHTTP01IngressNameOverride: "gateway-name",
							cmapi.IssueTemporaryCertificateAnnotation:       "true",
						},
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for an Gateway with a single valid TLS entry and HTTP01 annotations with no gateway class set",
			Issuer: acmeClusterIssuer,
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for an Gateway with a single valid TLS entry and HTTP01 annotations with a custom gateway class",
			Issuer: acmeClusterIssuer,
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressClassAnnotationKey:             "nginx-ing",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for an Gateway with a single valid TLS entry and HTTP01 annotations with a certificate Gateway class",
			Issuer: acmeClusterIssuer,
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey:            "issuer-name",
						cmapi.IngressACMEIssuerHTTP01IngressClassAnnotationKey: "cert-ing",
						cmapi.IngressClassAnnotationKey:                        "nginx-ing",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
						Annotations: map[string]string{
							cmacme.ACMECertificateHTTP01IngressClassOverride: "cert-ing",
						},
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "edit-in-place set to false should not trigger editing the Gateway in-place",
			Issuer: acmeClusterIssuer,
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressClassAnnotationKey:             "nginx-ing",
						cmacme.IngressEditInPlaceAnnotationKey:      "false",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "return a single DNS01 Certificate for a Gateway with a single valid TLS entry",
			Issuer: acmeClusterIssuer,
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:                "kubernetes.io/tls-acme should not trigger a Gateway",
			Issuer:              clusterIssuer,
			DefaultIssuerName:   "issuer-name",
			DefaultIssuerKind:   "ClusterIssuer",
			DefaultIssuerGroup:  "cert-manager.io",
			ClusterIssuerLister: []runtime.Object{clusterIssuer},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						"kubernetes.io/tls-acme": "true",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
		},
		{
			Name:         "should skip an invalid TLS entry (no TLS hosts specified)",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			ExpectedEvents: []string{
				`Warning BadConfig Skipped a listener block: spec.listeners[1].hostname: Required value: the hostname cannot be empty`,
				`Normal CreateCertificate Successfully created Certificate "example-com-tls"`,
			},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}, {
						Hostname: nil, // 🔥
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						Usages:     cmapi.DefaultKeyUsages(),
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
					},
				},
			},
		},
		{
			Name:         "should skip an invalid TLS entry (no TLS secret name specified)",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			ExpectedEvents: []string{
				`Warning BadConfig Skipped a listener block: spec.listeners[0].tls.certificateRef: Required value: listener has no certificateRefs`,
				`Normal CreateCertificate Successfully created Certificate "example-com-tls"`,
			},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode:            ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{},
						},
					}, {
						Hostname: ptrHostname("www.example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"www.example.com"},
						SecretName: "example-com-tls",
						Usages:     cmapi.DefaultKeyUsages(),
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
					},
				},
			},
		},
		{
			Name: "should error if the specified issuer is not found",
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "invalid-issuer-name",
					},
					UID: types.UID("gateway-name"),
				},
			},
		},
		{
			Name:         "should not return any certificates if a correct Certificate already exists",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "existing-crt",
								},
							},
						},
					}},
				},
			},
			DefaultIssuerKind:  "Issuer",
			DefaultIssuerGroup: "cert-manager.io",
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "issuer-name",
							Kind:  "Issuer",
							Group: "cert-manager.io",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should update a certificate if an incorrect Certificate exists",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "existing-crt",
								},
							},
						},
					}},
				},
			},
			CertificateLister: []runtime.Object{
				buildCertificate("existing-crt",
					gen.DefaultTestNamespace,
					buildGatewayOwnerReferences("gateway-name"),
				),
			},
			DefaultIssuerKind: "Issuer",
			ExpectedEvents:    []string{`Normal UpdateCertificate Successfully updated Certificate "existing-crt"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should update an existing Certificate resource with new labels if they do not match those specified on the Gateway",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuerNewFormat},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "cert-secret-name",
								},
							},
						},
					}},
				},
			},
			DefaultIssuerKind: "Issuer",
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cert-secret-name",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"a-different-value": "should be removed",
						},
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "cert-secret-name"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cert-secret-name",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "cert-secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should not update certificate if it does not belong to any Gateway",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressClassAnnotationKey:      "toot-ing",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "existing-crt",
								},
							},
						},
					}},
				},
			},
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: []metav1.OwnerReference{},
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should not update certificate if it does not belong to the Gateway",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressClassAnnotationKey:      "toot-ing",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "existing-crt",
								},
							},
						},
					}},
				},
			},
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildIngressOwnerReferences("not-gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should delete a Certificate if its secret name is not present in the Gateway",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("gateway-name"),
				},
			},
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
			ExpectedEvents: []string{`Normal DeleteCertificate Successfully deleted unrequired Certificate "existing-crt"`},
			ExpectedDelete: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
					},
				},
			},
		},
		{
			Name:         "should update a Certificate if it contains a Common Name that is not defined on the Gateway annotations",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IssuerKindAnnotationKey:        "Issuer",
						cmapi.IssuerGroupAnnotationKey:       "cert-manager.io",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						CommonName: "example-common-name",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "issuer-name",
							Kind:  "Issuer",
							Group: "cert-manager.io",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "example-com-tls"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "issuer-name",
							Kind:  "Issuer",
							Group: "cert-manager.io",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "if a Gateway contains multiple listeners that specify the same secretName, it should create a single Certificate",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IssuerKindAnnotationKey:        "Issuer",
						cmapi.IssuerGroupAnnotationKey:       "cert-manager.io",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}, {
						Hostname: ptrHostname("www.example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}, {
						Hostname: ptrHostname("foo.example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			ExpectedEvents: []string{
				`Normal CreateCertificate Successfully created Certificate "example-com-tls"`,
			},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com", "foo.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "issuer-name",
							Kind:  "Issuer",
							Group: "cert-manager.io",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "if a Gateway contains two listeners with different Secret names, it should create two Certificates",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IssuerKindAnnotationKey:        "Issuer",
						cmapi.IssuerGroupAnnotationKey:       "cert-manager.io",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("foo.example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "foo-example-com-tls",
								},
							},
						},
					}, {
						Hostname: ptrHostname("bar.example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "bar-example-com-tls",
								},
							},
						},
					}},
				},
			},
			ExpectedEvents: []string{
				`Normal CreateCertificate Successfully created Certificate "foo-example-com-tls"`,
				`Normal CreateCertificate Successfully created Certificate "bar-example-com-tls"`,
			},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "foo-example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"foo.example.com"},
						SecretName: "foo-example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "issuer-name",
							Kind:  "Issuer",
							Group: "cert-manager.io",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "bar-example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"bar.example.com"},
						SecretName: "bar-example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name:  "issuer-name",
							Kind:  "Issuer",
							Group: "cert-manager.io",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "Failure to translate the Gateway annotations",
			Issuer: acmeIssuer,
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IssuerKindAnnotationKey:        "Issuer",
						cmapi.IssuerGroupAnnotationKey:       "cert-manager.io",
						cmapi.RenewBeforeAnnotationKey:       "invalid renew before value",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			Err: true,
		},
		{
			Name:   "return a single Certificate for a Gateway with a single valid TLS entry with common-name and keyusage annotation",
			Issuer: acmeClusterIssuer,
			IngressLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.CommonNameAnnotationKey:               "my-cn",
						"cert-manager.io/usages":                    "signing,digital signature,content commitment",
					},
					UID: types.UID("gateway-name"),
				},
				Spec: gwapi.GatewaySpec{
					GatewayClassName: "test-gateway",
					Listeners: []gwapi.Listener{{
						Hostname: ptrHostname("example.com"),
						Port:     443,
						Protocol: gwapi.HTTPSProtocolType,
						TLS: &gwapi.GatewayTLSConfig{
							Mode: ptrMode(gwapi.TLSModeTerminate),
							CertificateRefs: []gwapi.SecretObjectReference{
								{
									Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
									Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
									Name:  "example-com-tls",
								},
							},
						},
					}},
				},
			},
			ClusterIssuerLister: []runtime.Object{acmeClusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "example-com-tls"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "example-com-tls",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildGatewayOwnerReferences("gateway-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"example.com"},
						CommonName: "my-cn",
						SecretName: "example-com-tls",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: []cmapi.KeyUsage{
							cmapi.UsageSigning,
							cmapi.UsageDigitalSignature,
							cmapi.UsageContentCommitment,
						},
					},
				},
			},
		},
		{
			Name:                "should not trigger a gateway sync if deleted in foreground",
			Issuer:              clusterIssuer,
			DefaultIssuerName:   "issuer-name",
			DefaultIssuerKind:   "ClusterIssuer",
			DefaultIssuerGroup:  "cert-manager.io",
			ClusterIssuerLister: []runtime.Object{clusterIssuer},
			IngressLike:         buildGatewayInDeletion(buildGateway("", "", map[string]string{cmapi.IngressIssuerNameAnnotationKey: ""}), &metav1.Time{}, []string{metav1.FinalizerDeleteDependents}),
		},
	}

	testFn := func(test testT) func(t *testing.T) {
		return func(t *testing.T) {
			var allCMObjects []runtime.Object
			allCMObjects = append(allCMObjects, test.IssuerLister...)
			allCMObjects = append(allCMObjects, test.ClusterIssuerLister...)
			allCMObjects = append(allCMObjects, test.CertificateLister...)
			var expectedActions []testpkg.Action
			for _, cr := range test.ExpectedCreate {
				expectedActions = append(expectedActions,
					testpkg.NewAction(coretesting.NewCreateActionWithOptions(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						cr.Namespace,
						cr,
						metav1.CreateOptions{
							FieldManager: "cert-manager-test",
						},
					)),
				)
			}
			for _, cr := range test.ExpectedUpdate {
				expectedActions = append(expectedActions,
					testpkg.NewAction(coretesting.NewUpdateActionWithOptions(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						cr.Namespace,
						cr,
						metav1.UpdateOptions{
							// TODO: set field manager here too
						},
					)),
				)
			}
			for _, cr := range test.ExpectedDelete {
				expectedActions = append(expectedActions,
					testpkg.NewAction(coretesting.NewDeleteActionWithOptions(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						cr.Namespace,
						cr.Name,
						metav1.DeleteOptions{
							// TODO: set field manager here too
						},
					)))
			}
			b := &testpkg.Builder{
				T:                  t,
				CertManagerObjects: allCMObjects,
				ExpectedActions:    expectedActions,
				ExpectedEvents:     test.ExpectedEvents,
			}
			b.Init()
			defer b.Stop()
			sync := SyncFnFor(b.Recorder, logr.Discard(), b.CMClient, b.SharedInformerFactory.Certmanager().V1().Certificates().Lister(), controllerpkg.IngressShimOptions{
				DefaultIssuerName:                 test.DefaultIssuerName,
				DefaultIssuerKind:                 test.DefaultIssuerKind,
				DefaultIssuerGroup:                test.DefaultIssuerGroup,
				DefaultAutoCertificateAnnotations: []string{"kubernetes.io/tls-acme"},
			}, "cert-manager-test")
			b.Start()

			err := sync(context.Background(), test.IngressLike)

			// If test.Err == true, err should not be nil and vice versa
			if test.Err == (err == nil) {
				t.Errorf("Expected error: %v, but got: %v", test.Err, err)
			}

			if err := b.AllEventsCalled(); err != nil {
				t.Error(err)
			}
			if err := b.AllActionsExecuted(); err != nil {
				t.Error(err)
			}
		}
	}
	t.Run("ingress-shim", func(t *testing.T) {
		for _, test := range testIngressShim {
			t.Run(test.Name, testFn(test))
		}
	})

	t.Run("gateway-shim", func(t *testing.T) {
		for _, test := range testGatewayShim {
			t.Run(test.Name, testFn(test))
		}
	})

}

func TestIssuerForIngress(t *testing.T) {
	type testT struct {
		Ingress       *networkingv1.Ingress
		DefaultName   string
		DefaultKind   string
		DefaultGroup  string
		ExpectedName  string
		ExpectedKind  string
		ExpectedGroup string
		ExpectedError error
	}
	tests := []testT{
		{
			Ingress: buildIngress("name", "namespace", map[string]string{
				cmapi.IngressIssuerNameAnnotationKey: "issuer",
				cmapi.IssuerGroupAnnotationKey:       "foo.bar",
			}),
			DefaultKind:   "Issuer",
			ExpectedName:  "issuer",
			ExpectedKind:  "Issuer",
			ExpectedGroup: "foo.bar",
		},
		{
			Ingress: buildIngress("name", "namespace", map[string]string{
				cmapi.IngressClusterIssuerNameAnnotationKey: "clusterissuer",
			}),
			ExpectedName: "clusterissuer",
			ExpectedKind: "ClusterIssuer",
		},
		{
			Ingress: buildIngress("name", "namespace", map[string]string{
				"kubernetes.io/tls-acme": "true",
			}),
			DefaultName:   "default-name",
			DefaultKind:   "ClusterIssuer",
			DefaultGroup:  "cert-manager.io",
			ExpectedName:  "default-name",
			ExpectedKind:  "ClusterIssuer",
			ExpectedGroup: "cert-manager.io",
		},
		{
			Ingress:       buildIngress("name", "namespace", nil),
			ExpectedError: errors.New("failed to determine issuer name to be used for ingress resource"),
		},
		{
			Ingress: buildIngress("name", "namespace", map[string]string{
				"kubernetes.io/tls-acme": "true",
			}),
			ExpectedError: errors.New("failed to determine issuer name to be used for ingress resource"),
		},
		{
			Ingress: buildIngress("name", "namespace", map[string]string{
				cmapi.IngressClusterIssuerNameAnnotationKey: "clusterissuer",
				cmapi.IngressIssuerNameAnnotationKey:        "issuer",
				cmapi.IssuerGroupAnnotationKey:              "group.io",
			}),
			ExpectedError: errors.New(`both "cert-manager.io/issuer" and "cert-manager.io/cluster-issuer" may not be set, both "cert-manager.io/cluster-issuer" and "cert-manager.io/issuer-group" may not be set`),
		},
	}
	for _, test := range tests {
		defaults := controllerpkg.IngressShimOptions{
			DefaultIssuerKind:  test.DefaultKind,
			DefaultIssuerName:  test.DefaultName,
			DefaultIssuerGroup: test.DefaultGroup,
		}
		name, kind, group, err := issuerForIngressLike(defaults, test.Ingress)
		if err != nil {
			if test.ExpectedError == nil || err.Error() != test.ExpectedError.Error() {
				t.Errorf("unexpected error, exp=%v got=%s", test.ExpectedError, err)
			}
		} else if test.ExpectedError != nil {
			t.Errorf("expected error but got nil: %s", test.ExpectedError)
		}

		if name != test.ExpectedName {
			t.Errorf("expected name to be %q but got %q", test.ExpectedName, name)
		}

		if kind != test.ExpectedKind {
			t.Errorf("expected kind to be %q but got %q", test.ExpectedKind, kind)
		}

		if group != test.ExpectedGroup {
			t.Errorf("expected group to be %q but got %q", test.ExpectedGroup, group)
		}
	}
}

func buildCertificate(name, namespace string, ownerReferences []metav1.OwnerReference) *cmapi.Certificate {
	return &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			OwnerReferences: ownerReferences,
		},
		Spec: cmapi.CertificateSpec{
			SecretName: name,
		},
	}
}

func buildIngress(name, namespace string, annotations map[string]string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
			UID:         types.UID(name),
		},
	}
}

func buildGateway(name, namespace string, annotations map[string]string) *gwapi.Gateway {
	return &gwapi.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
			UID:         types.UID(name),
		},
	}
}

func buildIngressOwnerReferences(name string) []metav1.OwnerReference {
	return []metav1.OwnerReference{
		*metav1.NewControllerRef(buildIngress(name, gen.DefaultTestNamespace, nil), ingressV1GVK),
	}
}

// The Gateway name and UID are set to the same.
func buildGatewayOwnerReferences(name string) []metav1.OwnerReference {
	return []metav1.OwnerReference{
		*metav1.NewControllerRef(buildGateway(name, gen.DefaultTestNamespace, nil), gatewayGVK),
	}
}

func ptrHostname(hostname string) *gwapi.Hostname {
	h := gwapi.Hostname(hostname)
	return &h
}

func ptrMode(mode gwapi.TLSModeType) *gwapi.TLSModeType {
	return &mode
}

func Test_validateGatewayListenerBlock(t *testing.T) {
	tests := []struct {
		name     string
		ingLike  metav1.Object
		listener gwapi.Listener
		wantErr  string
	}{
		{
			name: "empty TLS block",
			ingLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway",
					Namespace: gen.DefaultTestNamespace,
				},
			},
			listener: gwapi.Listener{
				Hostname: ptrHostname("example.com"),
				Port:     gwapi.PortNumber(443),
				Protocol: gwapi.HTTPSProtocolType,
			},
			wantErr: "spec.listeners[0].tls: Required value: the TLS block cannot be empty",
		},
		{
			name: "empty hostname",
			ingLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway",
					Namespace: gen.DefaultTestNamespace,
				},
			},
			listener: gwapi.Listener{
				Hostname: ptrHostname(""),
				Port:     gwapi.PortNumber(443),
				Protocol: gwapi.HTTPSProtocolType,
				TLS: &gwapi.GatewayTLSConfig{
					Mode: ptrMode(gwapi.TLSModeTerminate),
					CertificateRefs: []gwapi.SecretObjectReference{
						{
							Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
							Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
							Name:  "example-com",
						},
					},
				},
			},
			wantErr: "spec.listeners[0].hostname: Required value: the hostname cannot be empty",
		},
		{
			name: "empty group",
			ingLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "example",
					Namespace: gen.DefaultTestNamespace,
				},
			},
			listener: gwapi.Listener{
				Hostname: ptrHostname("example.com"),
				Port:     gwapi.PortNumber(443),
				Protocol: gwapi.HTTPSProtocolType,
				TLS: &gwapi.GatewayTLSConfig{
					Mode: ptrMode(gwapi.TLSModeTerminate),
					CertificateRefs: []gwapi.SecretObjectReference{
						{
							Group: func() *gwapi.Group { g := gwapi.Group(""); return &g }(),
							Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
							Name:  "example-com",
						},
					},
				},
			},
			// no group is now supported
			wantErr: "",
		},
		{
			name: "unsupported group",
			listener: gwapi.Listener{
				Hostname: ptrHostname("example.com"),
				Port:     gwapi.PortNumber(443),
				Protocol: gwapi.HTTPSProtocolType,
				TLS: &gwapi.GatewayTLSConfig{
					Mode: ptrMode(gwapi.TLSModeTerminate),
					CertificateRefs: []gwapi.SecretObjectReference{
						{
							Group: func() *gwapi.Group { g := gwapi.Group("invalid"); return &g }(),
							Kind:  func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
							Name:  "example-com-tls",
						},
					},
				},
			},
			wantErr: "spec.listeners[0].tls.certificateRef[0].group: Unsupported value: \"invalid\": supported values: \"core\", \"\"",
		},
		{
			name: "unsupported kind",
			listener: gwapi.Listener{
				Hostname: ptrHostname("example.com"),
				Port:     gwapi.PortNumber(443),
				Protocol: gwapi.HTTPSProtocolType,
				TLS: &gwapi.GatewayTLSConfig{
					Mode: ptrMode(gwapi.TLSModeTerminate),
					CertificateRefs: []gwapi.SecretObjectReference{
						{
							Group: func() *gwapi.Group { g := gwapi.Group("core"); return &g }(),
							Kind:  func() *gwapi.Kind { k := gwapi.Kind("SomeOtherKind"); return &k }(),
							Name:  "example-com",
						},
					},
				},
			},
			wantErr: "spec.listeners[0].tls.certificateRef[0].kind: Unsupported value: \"SomeOtherKind\": supported values: \"Secret\", \"\"",
		},
		{
			name: "cross-namespace secret ref",
			ingLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "example",
					Namespace: gen.DefaultTestNamespace,
				},
			},
			listener: gwapi.Listener{
				Hostname: ptrHostname("example.com"),
				Port:     gwapi.PortNumber(443),
				Protocol: gwapi.HTTPSProtocolType,
				TLS: &gwapi.GatewayTLSConfig{
					Mode: ptrMode(gwapi.TLSModeTerminate),
					CertificateRefs: []gwapi.SecretObjectReference{
						{
							Group:     func() *gwapi.Group { g := gwapi.Group(""); return &g }(),
							Kind:      func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
							Name:      "example-com",
							Namespace: func() *gwapi.Namespace { n := gwapi.Namespace("another-namespace"); return &n }(),
						},
					},
				},
			},
			wantErr: "spec.listeners[0].tls.certificateRef[0].namespace: Invalid value: \"another-namespace\": cross-namespace secret references are not allowed in listeners",
		},
		{
			name: "same namespace secret ref",
			ingLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "example",
					Namespace: "another-namespace",
				},
			},
			listener: gwapi.Listener{
				Hostname: ptrHostname("example.com"),
				Port:     gwapi.PortNumber(443),
				Protocol: gwapi.HTTPSProtocolType,
				TLS: &gwapi.GatewayTLSConfig{
					Mode: ptrMode(gwapi.TLSModeTerminate),
					CertificateRefs: []gwapi.SecretObjectReference{
						{
							Group:     func() *gwapi.Group { g := gwapi.Group(""); return &g }(),
							Kind:      func() *gwapi.Kind { k := gwapi.Kind("Secret"); return &k }(),
							Name:      "example-com",
							Namespace: func() *gwapi.Namespace { n := gwapi.Namespace("another-namespace"); return &n }(),
						},
					},
				},
			},
			wantErr: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErr := validateGatewayListenerBlock(field.NewPath("spec", "listeners").Index(0), test.listener, test.ingLike).ToAggregate()
			if test.wantErr == "" {
				assert.NoError(t, gotErr)
			} else {
				assert.EqualError(t, gotErr, test.wantErr)
			}
		})
	}
}

func Test_findCertificatesToBeRemoved(t *testing.T) {
	tests := []struct {
		name            string
		givenCerts      []*cmapi.Certificate
		ingLike         metav1.Object
		wantToBeRemoved []string
	}{
		{
			name: "should not remove Certificate when not owned by the Ingress",
			givenCerts: []*cmapi.Certificate{{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "cert-1",
					Namespace:       gen.DefaultTestNamespace,
					OwnerReferences: buildGatewayOwnerReferences("ingress-1"),
				}, Spec: cmapi.CertificateSpec{
					SecretName: "secret-name",
				}},
			},
			ingLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-2", Namespace: gen.DefaultTestNamespace, UID: "ingress-2"},
				Spec:       networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{{SecretName: "secret-name"}}},
			},
			wantToBeRemoved: nil,
		},
		{
			name: "should not remove Certificate when Ingress references the secretName of the Certificate",
			givenCerts: []*cmapi.Certificate{{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "cert-1",
					Namespace:       gen.DefaultTestNamespace,
					OwnerReferences: buildGatewayOwnerReferences("ingress-1"),
				}, Spec: cmapi.CertificateSpec{
					SecretName: "secret-name",
				}},
			},
			ingLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-1", Namespace: gen.DefaultTestNamespace, UID: "ingress-1"},
				Spec:       networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{{SecretName: "secret-name"}}},
			},
			wantToBeRemoved: nil,
		},
		{
			name: "should remove Certificate when Ingress does not reference the secretName of the Certificate",
			givenCerts: []*cmapi.Certificate{{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "cert-1",
					Namespace:       gen.DefaultTestNamespace,
					OwnerReferences: buildGatewayOwnerReferences("ingress-1"),
				}, Spec: cmapi.CertificateSpec{
					SecretName: "secret-name",
				}},
			},
			ingLike: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-1", Namespace: gen.DefaultTestNamespace, UID: "ingress-1"},
			},
			wantToBeRemoved: []string{"cert-1"},
		},
		{
			name: "should not remove Certificate when not owned by the Gateway",
			givenCerts: []*cmapi.Certificate{{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "cert-1",
					Namespace:       gen.DefaultTestNamespace,
					OwnerReferences: buildGatewayOwnerReferences("gw-1"),
				}, Spec: cmapi.CertificateSpec{
					SecretName: "secret-name",
				}},
			},
			ingLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw-2", Namespace: gen.DefaultTestNamespace, UID: "gw-2"},
				Spec: gwapi.GatewaySpec{Listeners: []gwapi.Listener{{
					TLS: &gwapi.GatewayTLSConfig{CertificateRefs: []gwapi.SecretObjectReference{
						{
							Name: "secret-name",
						},
					}},
				}}},
			},
			wantToBeRemoved: nil,
		},
		{
			name: "should remove Certificate when Gateway does not reference the secretName of the Certificate in one of its listers",
			givenCerts: []*cmapi.Certificate{{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "cert-1",
					Namespace:       gen.DefaultTestNamespace,
					OwnerReferences: buildGatewayOwnerReferences("gw-1"),
				}, Spec: cmapi.CertificateSpec{
					SecretName: "secret-name",
				}},
			},
			ingLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw-1", Namespace: gen.DefaultTestNamespace, UID: "gw-1"},
				Spec: gwapi.GatewaySpec{Listeners: []gwapi.Listener{
					{TLS: &gwapi.GatewayTLSConfig{CertificateRefs: []gwapi.SecretObjectReference{{Name: "not-secret-name"}}}},
				}},
			},
			wantToBeRemoved: []string{"cert-1"},
		},
		{
			name: "should not remove Certificate when the Gateway references the secretName of the Certificate in one of its listers",
			givenCerts: []*cmapi.Certificate{{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "cert-1",
					Namespace:       gen.DefaultTestNamespace,
					OwnerReferences: buildGatewayOwnerReferences("gw-1"),
				}, Spec: cmapi.CertificateSpec{
					SecretName: "secret-name",
				}},
			},
			ingLike: &gwapi.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw-1", Namespace: gen.DefaultTestNamespace, UID: "gw-1"},
				Spec: gwapi.GatewaySpec{Listeners: []gwapi.Listener{
					{TLS: &gwapi.GatewayTLSConfig{CertificateRefs: []gwapi.SecretObjectReference{{Name: "secret-name"}}}},
				}},
			},
			wantToBeRemoved: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotCerts := findCertificatesToBeRemoved(test.givenCerts, test.ingLike)
			assert.Equal(t, test.wantToBeRemoved, gotCerts)
		})
	}
}

func Test_secretNameUsedIn_nilPointerGateway(t *testing.T) {
	got := secretNameUsedIn("secret-name", &gwapi.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-1", Namespace: gen.DefaultTestNamespace, UID: "gw-1"},
		Spec: gwapi.GatewaySpec{Listeners: []gwapi.Listener{
			{TLS: nil},
			{TLS: &gwapi.GatewayTLSConfig{CertificateRefs: nil}},
			{TLS: &gwapi.GatewayTLSConfig{CertificateRefs: []gwapi.SecretObjectReference{{Name: "secret-name"}}}},
		}},
	})
	assert.Equal(t, true, got)

	got = secretNameUsedIn("secret-name", &gwapi.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-1", Namespace: gen.DefaultTestNamespace, UID: "gw-1"},
		Spec: gwapi.GatewaySpec{Listeners: []gwapi.Listener{
			{TLS: nil},
			{TLS: &gwapi.GatewayTLSConfig{CertificateRefs: nil}},
		}},
	})
	assert.Equal(t, false, got)
}

func buildIngressInDeletion(ingress *networkingv1.Ingress, deletionTimestamp *metav1.Time, finalizers []string) *networkingv1.Ingress {
	if ingress == nil {
		ingress = buildIngress("test-ingress", gen.DefaultTestNamespace, nil)
	}

	ingress.SetDeletionTimestamp(deletionTimestamp)
	ingress.SetFinalizers(finalizers)
	return ingress
}

func buildGatewayInDeletion(gateway *gwapi.Gateway, deletionTimestamp *metav1.Time, finalizers []string) *gwapi.Gateway {
	if gateway == nil {
		gateway = buildGateway("test-gw", gen.DefaultTestNamespace, nil)
	}

	gateway.SetDeletionTimestamp(deletionTimestamp)
	gateway.SetFinalizers(finalizers)
	return gateway
}

func Test_isDeletedInForeground(t *testing.T) {
	type testT struct {
		DeletionTimestamp *metav1.Time
		Finalizers        []string
		SkipSync          bool
	}

	tests := []testT{
		{DeletionTimestamp: nil, Finalizers: nil, SkipSync: false},
		{DeletionTimestamp: nil, Finalizers: []string{}, SkipSync: false},
		{DeletionTimestamp: nil, Finalizers: []string{"cert-lock"}, SkipSync: false},
		{DeletionTimestamp: &metav1.Time{}, Finalizers: []string{"cert-lock"}, SkipSync: true},
		{DeletionTimestamp: &metav1.Time{}, Finalizers: nil, SkipSync: true},
		{DeletionTimestamp: &metav1.Time{}, Finalizers: []string{}, SkipSync: true},
		{DeletionTimestamp: nil, Finalizers: []string{metav1.FinalizerDeleteDependents}, SkipSync: true},
		{DeletionTimestamp: &metav1.Time{}, Finalizers: []string{"cert-lock", metav1.FinalizerDeleteDependents}, SkipSync: true},
	}

	t.Run("should skip ingress sync if being deleted in foreground", func(t *testing.T) {
		for _, test := range tests {
			skipIngressSync := isDeletedInForeground(buildIngressInDeletion(nil, test.DeletionTimestamp, test.Finalizers))
			if skipIngressSync != test.SkipSync {
				t.Errorf("Expected skipIngressSync=%v for deletionTimestamp %#v, finalizers %#v", test.SkipSync, test.DeletionTimestamp, test.Finalizers)
			}
		}
	})

	t.Run("should skip gateway sync if being deleted in foreground", func(t *testing.T) {
		for _, test := range tests {
			skipGatewaySync := isDeletedInForeground(buildGatewayInDeletion(nil, test.DeletionTimestamp, test.Finalizers))
			if skipGatewaySync != test.SkipSync {
				t.Errorf("Expected skipGatewaySync=%v for deletionTimestamp %#v, finalizers %#v", test.SkipSync, test.DeletionTimestamp, test.Finalizers)
			}
		}
	})
}
