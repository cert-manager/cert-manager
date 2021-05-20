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

package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

const testAcmeTLSAnnotation = "kubernetes.io/tls-acme"

func TestShouldSync(t *testing.T) {
	type testT struct {
		Annotations map[string]string
		ShouldSync  bool
	}
	tests := []testT{
		{
			Annotations: map[string]string{cmapi.IngressIssuerNameAnnotationKey: ""},
			ShouldSync:  true,
		},
		{
			Annotations: map[string]string{cmapi.IngressClusterIssuerNameAnnotationKey: ""},
			ShouldSync:  true,
		},
		{
			Annotations: map[string]string{testAcmeTLSAnnotation: "true"},
			ShouldSync:  true,
		},
		{
			Annotations: map[string]string{testAcmeTLSAnnotation: "false"},
			ShouldSync:  false,
		},
		{
			Annotations: map[string]string{testAcmeTLSAnnotation: ""},
			ShouldSync:  false,
		},
		{
			ShouldSync: false,
		},
	}
	for _, test := range tests {
		shouldSync := shouldSync(buildIngress("", "", test.Annotations), []string{"kubernetes.io/tls-acme"})
		if shouldSync != test.ShouldSync {
			t.Errorf("Expected shouldSync=%v for annotations %#v", test.ShouldSync, test.Annotations)
		}
	}
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
		Ingress             *networkingv1beta1.Ingress
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
	tests := []testT{
		{
			Name:   "return a single Certificate for an ingress with a single valid TLS entry and common-name annotation",
			Issuer: acmeClusterIssuer,
			Ingress: &networkingv1beta1.Ingress{
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
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Name:   "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations using edit-in-place",
			Issuer: acmeClusterIssuer,
			Ingress: &networkingv1beta1.Ingress{
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
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Ingress: &networkingv1beta1.Ingress{
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
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Ingress: &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Ingress: &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressClassAnnotationKey:             "nginx-ing",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Ingress: &networkingv1beta1.Ingress{
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
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Name:   "edit-in-place set to false should not trigger editing the ingress in-place",
			Issuer: acmeClusterIssuer,
			Ingress: &networkingv1beta1.Ingress{
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
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Ingress: &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressClusterIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Ingress: &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						testAcmeTLSAnnotation: "true",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
				`Warning BadConfig TLS entry 0 is invalid: secret "example-com-tls-invalid" for ingress TLS has no hosts specified`,
				`Normal CreateCertificate Successfully created Certificate "example-com-tls"`,
			},
			Ingress: &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
				`Warning BadConfig TLS entry 0 is invalid: TLS entry for hosts [example.com] must specify a secretName`,
				`Normal CreateCertificate Successfully created Certificate "example-com-tls"`,
			},
			Ingress: &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Ingress: &networkingv1beta1.Ingress{
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
			Ingress: &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Ingress: &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
					buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
				),
			},
			DefaultIssuerKind: "Issuer",
			ExpectedEvents:    []string{`Normal UpdateCertificate Successfully updated Certificate "existing-crt"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Name:         "should update an existing Certificate resource with new labels if they do not match those specified on the Ingress",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuerNewFormat},
			Ingress: &networkingv1beta1.Ingress{
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
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Name:         "should not update certificate if it does not belong to any ingress",
			Issuer:       acmeIssuer,
			IssuerLister: []runtime.Object{acmeIssuer},
			Ingress: &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressClassAnnotationKey:      "toot-ing",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
			Ingress: &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IngressClassAnnotationKey:      "toot-ing",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("not-ingress-name", gen.DefaultTestNamespace),
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
			Ingress: &networkingv1beta1.Ingress{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
			Ingress: &networkingv1beta1.Ingress{
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
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
				`Warning BadConfig Duplicate TLS entry for secretName "example-com-tls"`,
			},
			Ingress: &networkingv1beta1.Ingress{
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
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
			Ingress: &networkingv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						cmapi.IngressIssuerNameAnnotationKey: "issuer-name",
						cmapi.IssuerKindAnnotationKey:        "Issuer",
						cmapi.IssuerGroupAnnotationKey:       "cert-manager.io",
						cmapi.RenewBeforeAnnotationKey:       "invalid renew before value",
					},
					UID: types.UID("ingress-name"),
				},
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
			Ingress: &networkingv1beta1.Ingress{
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
				Spec: networkingv1beta1.IngressSpec{
					TLS: []networkingv1beta1.IngressTLS{
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
						OwnerReferences: buildOwnerReferences("ingress-name", gen.DefaultTestNamespace),
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
					testpkg.NewAction(coretesting.NewCreateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						cr.Namespace,
						cr,
					)),
				)
			}
			for _, cr := range test.ExpectedUpdate {
				expectedActions = append(expectedActions,
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						cr.Namespace,
						cr,
					)),
				)
			}
			for _, cr := range test.ExpectedDelete {
				expectedActions = append(expectedActions,
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						cr.Namespace,
						cr.Name,
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
			c := &controller{
				kClient:             b.Client,
				cmClient:            b.CMClient,
				recorder:            b.Recorder,
				issuerLister:        b.SharedInformerFactory.Certmanager().V1().Issuers().Lister(),
				clusterIssuerLister: b.SharedInformerFactory.Certmanager().V1().ClusterIssuers().Lister(),
				certificateLister:   b.SharedInformerFactory.Certmanager().V1().Certificates().Lister(),
				defaults: defaults{
					issuerName:                 test.DefaultIssuerName,
					issuerKind:                 test.DefaultIssuerKind,
					issuerGroup:                test.DefaultIssuerGroup,
					autoCertificateAnnotations: []string{testAcmeTLSAnnotation},
				},
				helper: &fakeHelper{issuer: test.Issuer},
			}
			b.Start()

			err := c.Sync(context.Background(), test.Ingress)

			// If test.Err == true, err should not be nil and vice versa
			if test.Err == (err == nil) {
				t.Errorf("Expected error: %v, but got: %v", test.Err, err)
			}

			if err := b.AllEventsCalled(); err != nil {
				t.Error(err)
			}
			if err := b.AllReactorsCalled(); err != nil {
				t.Errorf("Not all expected reactors were called: %v", err)
			}
			if err := b.AllActionsExecuted(); err != nil {
				t.Errorf(err.Error())
			}
		}
	}
	for _, test := range tests {
		t.Run(test.Name, testFn(test))
	}
}

type fakeHelper struct {
	issuer cmapi.GenericIssuer
}

func (f *fakeHelper) GetGenericIssuer(ref cmmeta.ObjectReference, ns string) (cmapi.GenericIssuer, error) {
	if f.issuer == nil {
		return nil, fmt.Errorf("no issuer specified on fake helper")
	}
	return f.issuer, nil
}

func TestIssuerForIngress(t *testing.T) {
	type testT struct {
		Ingress       *networkingv1beta1.Ingress
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
				testAcmeTLSAnnotation: "true",
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
				testAcmeTLSAnnotation: "true",
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
		c := &controller{
			defaults: defaults{
				issuerKind:  test.DefaultKind,
				issuerName:  test.DefaultName,
				issuerGroup: test.DefaultGroup,
			},
		}
		name, kind, group, err := c.issuerForIngress(test.Ingress)
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

func buildIngress(name, namespace string, annotations map[string]string) *networkingv1beta1.Ingress {
	return &networkingv1beta1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
			UID:         types.UID(name),
		},
	}
}

func buildOwnerReferences(name, namespace string) []metav1.OwnerReference {
	return []metav1.OwnerReference{
		*metav1.NewControllerRef(buildIngress(name, namespace, nil), ingressGVK),
	}
}
