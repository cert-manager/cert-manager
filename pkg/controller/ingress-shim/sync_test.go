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

package controller

import (
	"reflect"
	"testing"

	extv1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmfake "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

const testAcmeTLSAnnotation = "kubernetes.io/tls-acme"

func strPtr(s string) *string {
	return &s
}

func TestShouldSync(t *testing.T) {
	type testT struct {
		Annotations map[string]string
		ShouldSync  bool
	}
	tests := []testT{
		{
			Annotations: map[string]string{issuerNameAnnotation: ""},
			ShouldSync:  true,
		},
		{
			Annotations: map[string]string{clusterIssuerNameAnnotation: ""},
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
			Annotations: map[string]string{acmeIssuerChallengeTypeAnnotation: ""},
			ShouldSync:  true,
		},
		{
			Annotations: map[string]string{acmeIssuerDNS01ProviderNameAnnotation: ""},
			ShouldSync:  true,
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

func TestBuildCertificates(t *testing.T) {
	clusterIssuer := gen.ClusterIssuer("issuer-name")
	acmeIssuer := gen.Issuer("issuer-name", gen.SetIssuerACME(v1alpha1.ACMEIssuer{}))
	acmeClusterIssuer := gen.ClusterIssuer("issuer-name", gen.SetIssuerACME(v1alpha1.ACMEIssuer{}))
	type testT struct {
		Name                string
		Ingress             *extv1beta1.Ingress
		Issuer              v1alpha1.GenericIssuer
		IssuerLister        []*v1alpha1.Issuer
		ClusterIssuerLister []*v1alpha1.ClusterIssuer
		CertificateLister   []*v1alpha1.Certificate
		DefaultIssuerName   string
		DefaultIssuerKind   string
		Err                 bool
		ExpectedCreate      []*v1alpha1.Certificate
		ExpectedUpdate      []*v1alpha1.Certificate
	}
	tests := []testT{
		{
			Name:   "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations using edit-in-place",
			Issuer: acmeClusterIssuer,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						clusterIssuerNameAnnotation:       "issuer-name",
						acmeIssuerChallengeTypeAnnotation: "http01",
						editInPlaceAnnotation:             "true",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{acmeClusterIssuer},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", gen.DefaultTestNamespace, nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.DomainSolverConfig{
								{
									Domains: []string{"example.com", "www.example.com"},
									SolverConfig: v1alpha1.SolverConfig{
										HTTP01: &v1alpha1.HTTP01SolverConfig{
											Ingress: "ingress-name",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations with no ingress class set",
			Issuer: acmeClusterIssuer,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						clusterIssuerNameAnnotation:       "issuer-name",
						acmeIssuerChallengeTypeAnnotation: "http01",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{acmeClusterIssuer},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", gen.DefaultTestNamespace, nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.DomainSolverConfig{
								{
									Domains: []string{"example.com", "www.example.com"},
									SolverConfig: v1alpha1.SolverConfig{
										HTTP01: &v1alpha1.HTTP01SolverConfig{},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations with a custom ingress class",
			Issuer: acmeClusterIssuer,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						clusterIssuerNameAnnotation:       "issuer-name",
						acmeIssuerChallengeTypeAnnotation: "http01",
						ingressClassAnnotation:            "nginx-ing",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{acmeClusterIssuer},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", gen.DefaultTestNamespace, nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.DomainSolverConfig{
								{
									Domains: []string{"example.com", "www.example.com"},
									SolverConfig: v1alpha1.SolverConfig{
										HTTP01: &v1alpha1.HTTP01SolverConfig{
											IngressClass: strPtr("nginx-ing"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:   "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations with a certificate ingress class",
			Issuer: acmeClusterIssuer,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						clusterIssuerNameAnnotation:            "issuer-name",
						acmeIssuerChallengeTypeAnnotation:      "http01",
						acmeIssuerHTTP01IngressClassAnnotation: "cert-ing",
						ingressClassAnnotation:                 "nginx-ing",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{acmeClusterIssuer},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", gen.DefaultTestNamespace, nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.DomainSolverConfig{
								{
									Domains: []string{"example.com", "www.example.com"},
									SolverConfig: v1alpha1.SolverConfig{
										HTTP01: &v1alpha1.HTTP01SolverConfig{
											IngressClass: strPtr("cert-ing"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:   "edit-in-place set to false should not trigger editing the ingress in-place",
			Issuer: acmeClusterIssuer,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						clusterIssuerNameAnnotation:       "issuer-name",
						acmeIssuerChallengeTypeAnnotation: "http01",
						ingressClassAnnotation:            "nginx-ing",
						editInPlaceAnnotation:             "false",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{acmeClusterIssuer},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", gen.DefaultTestNamespace, nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.DomainSolverConfig{
								{
									Domains: []string{"example.com", "www.example.com"},
									SolverConfig: v1alpha1.SolverConfig{
										HTTP01: &v1alpha1.HTTP01SolverConfig{
											IngressClass: strPtr("nginx-ing"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:   "should error when an ingress specifies dns01 challenge type but no challenge provider",
			Issuer: acmeClusterIssuer,
			Err:    true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						clusterIssuerNameAnnotation:       "issuer-name",
						acmeIssuerChallengeTypeAnnotation: "dns01",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{acmeClusterIssuer},
		},
		{
			Name:   "should error when an invalid ACME challenge type is specified",
			Issuer: acmeClusterIssuer,
			Err:    true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						clusterIssuerNameAnnotation:       "issuer-name",
						acmeIssuerChallengeTypeAnnotation: "invalid-challenge-type",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{acmeClusterIssuer},
		},
		{
			Name:   "return a single DNS01 Certificate for an ingress with a single valid TLS entry and DNS01 annotations",
			Issuer: acmeClusterIssuer,
			Err:    true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						clusterIssuerNameAnnotation:           "issuer-name",
						acmeIssuerChallengeTypeAnnotation:     "dns01",
						acmeIssuerDNS01ProviderNameAnnotation: "fake-dns",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{acmeClusterIssuer},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", gen.DefaultTestNamespace, nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.DomainSolverConfig{
								{
									Domains: []string{"example.com", "www.example.com"},
									SolverConfig: v1alpha1.SolverConfig{
										DNS01: &v1alpha1.DNS01SolverConfig{
											Provider: "fake-dns",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:   "should error when no challenge type is provided",
			Issuer: acmeClusterIssuer,
			Err:    true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						clusterIssuerNameAnnotation: "issuer-name",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{acmeClusterIssuer},
		},
		{
			Name:                "should return a basic certificate when no provider specific config is provided",
			Issuer:              clusterIssuer,
			DefaultIssuerName:   "issuer-name",
			DefaultIssuerKind:   "ClusterIssuer",
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{clusterIssuer},
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com", "www.example.com"},
							SecretName: "example-com-tls",
						},
					},
				},
			},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", gen.DefaultTestNamespace, nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
					},
				},
			},
		},
		{
			Name:         "should return an error when no TLS hosts are specified",
			Issuer:       acmeIssuer,
			IssuerLister: []*v1alpha1.Issuer{acmeIssuer},
			Err:          true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						issuerNameAnnotation: "issuer-name",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							SecretName: "example-com-tls",
						},
					},
				},
			},
		},
		{
			Name:   "should return an error when no TLS secret name is specified",
			Issuer: acmeIssuer,
			Err:    true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						issuerNameAnnotation: "issuer-name",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts: []string{"example.com"},
						},
					},
				},
			},
			IssuerLister: []*v1alpha1.Issuer{acmeIssuer},
		},
		{
			Name: "should error if the specified issuer is not found",
			Err:  true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						issuerNameAnnotation: "invalid-issuer-name",
					},
				},
			},
		},
		{
			Name:         "should not return any certificates if a correct Certificate already exists",
			Issuer:       acmeIssuer,
			IssuerLister: []*v1alpha1.Issuer{acmeIssuer},
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						issuerNameAnnotation:              "issuer-name",
						acmeIssuerChallengeTypeAnnotation: "http01",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "existing-crt",
						},
					},
				},
			},
			CertificateLister: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-crt",
						Namespace: gen.DefaultTestNamespace,
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.DomainSolverConfig{
								{
									Domains: []string{"example.com"},
									SolverConfig: v1alpha1.SolverConfig{
										HTTP01: &v1alpha1.HTTP01SolverConfig{
											Ingress: "",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:         "should update a certificate if an incorrect Certificate exists",
			Issuer:       acmeIssuer,
			IssuerLister: []*v1alpha1.Issuer{acmeIssuer},
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						issuerNameAnnotation:              "issuer-name",
						acmeIssuerChallengeTypeAnnotation: "http01",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "existing-crt",
						},
					},
				},
			},
			CertificateLister: []*v1alpha1.Certificate{buildCertificate("existing-crt", gen.DefaultTestNamespace)},
			ExpectedUpdate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-crt",
						Namespace: gen.DefaultTestNamespace,
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.DomainSolverConfig{
								{
									Domains: []string{"example.com"},
									SolverConfig: v1alpha1.SolverConfig{
										HTTP01: &v1alpha1.HTTP01SolverConfig{
											Ingress: "",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:         "should update a certificate's config if an incorrect Certificate exists",
			Issuer:       acmeIssuer,
			IssuerLister: []*v1alpha1.Issuer{acmeIssuer},
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						issuerNameAnnotation:              "issuer-name",
						acmeIssuerChallengeTypeAnnotation: "http01",
						ingressClassAnnotation:            "toot-ing",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "existing-crt",
						},
					},
				},
			},
			CertificateLister: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-crt",
						Namespace: gen.DefaultTestNamespace,
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.DomainSolverConfig{
								{
									Domains: []string{"wrong-example.com"},
									SolverConfig: v1alpha1.SolverConfig{
										HTTP01: &v1alpha1.HTTP01SolverConfig{
											Ingress: "wrong-ingress",
										},
									},
								},
							},
						},
					},
				},
			},
			ExpectedUpdate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-crt",
						Namespace: gen.DefaultTestNamespace,
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.DomainSolverConfig{
								{
									Domains: []string{"example.com"},
									SolverConfig: v1alpha1.SolverConfig{
										HTTP01: &v1alpha1.HTTP01SolverConfig{
											Ingress:      "",
											IngressClass: strPtr("toot-ing"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name:         "should update a Certificate correctly if an existing one of a different type exists",
			Issuer:       acmeIssuer,
			IssuerLister: []*v1alpha1.Issuer{acmeIssuer},
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: gen.DefaultTestNamespace,
					Annotations: map[string]string{
						issuerNameAnnotation:              "issuer-name",
						acmeIssuerChallengeTypeAnnotation: "http01",
						ingressClassAnnotation:            "toot-ing",
					},
				},
				Spec: extv1beta1.IngressSpec{
					TLS: []extv1beta1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "existing-crt",
						},
					},
				},
			},
			CertificateLister: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-crt",
						Namespace: gen.DefaultTestNamespace,
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
					},
				},
			},
			ExpectedUpdate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-crt",
						Namespace: gen.DefaultTestNamespace,
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com"},
						SecretName: "existing-crt",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.DomainSolverConfig{
								{
									Domains: []string{"example.com"},
									SolverConfig: v1alpha1.SolverConfig{
										HTTP01: &v1alpha1.HTTP01SolverConfig{
											Ingress:      "",
											IngressClass: strPtr("toot-ing"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	testFn := func(test testT) func(t *testing.T) {
		return func(t *testing.T) {
			cmClient := cmfake.NewSimpleClientset()
			factory := cminformers.NewSharedInformerFactory(cmClient, 0)
			issuerInformer := factory.Certmanager().V1alpha1().Issuers()
			clusterIssuerInformer := factory.Certmanager().V1alpha1().ClusterIssuers()
			certificatesInformer := factory.Certmanager().V1alpha1().Certificates()
			for _, i := range test.IssuerLister {
				issuerInformer.Informer().GetIndexer().Add(i)
			}
			for _, i := range test.ClusterIssuerLister {
				clusterIssuerInformer.Informer().GetIndexer().Add(i)
			}
			for _, i := range test.CertificateLister {
				certificatesInformer.Informer().GetIndexer().Add(i)
			}
			c := &Controller{
				issuerLister:        issuerInformer.Lister(),
				clusterIssuerLister: clusterIssuerInformer.Lister(),
				certificateLister:   certificatesInformer.Lister(),
				defaults: defaults{
					issuerName: test.DefaultIssuerName,
					issuerKind: test.DefaultIssuerKind,
				},
			}
			issuerKind := "Issuer"
			if _, ok := test.Issuer.(*v1alpha1.ClusterIssuer); ok {
				issuerKind = "ClusterIssuer"
			}
			createCrts, updateCrts, err := c.buildCertificates(test.Ingress, test.Issuer, issuerKind)
			if err != nil && !test.Err {
				t.Errorf("Expected no error, but got: %s", err)
			}
			if !reflect.DeepEqual(createCrts, test.ExpectedCreate) {
				t.Errorf("Expected to create %+v but got %+v", test.ExpectedCreate, createCrts)
			}

			if !reflect.DeepEqual(updateCrts, test.ExpectedUpdate) {
				t.Errorf("Expected to update %+v but got %+v", test.ExpectedUpdate, updateCrts)
			}
		}
	}
	for _, test := range tests {
		t.Run(test.Name, testFn(test))
	}
}

func TestIssuerForIngress(t *testing.T) {
	type testT struct {
		Ingress      *extv1beta1.Ingress
		DefaultName  string
		DefaultKind  string
		ExpectedName string
		ExpectedKind string
	}
	tests := []testT{
		{
			Ingress: buildIngress("name", "namespace", map[string]string{
				issuerNameAnnotation: "issuer",
			}),
			ExpectedName: "issuer",
			ExpectedKind: "Issuer",
		},
		{
			Ingress: buildIngress("name", "namespace", map[string]string{
				clusterIssuerNameAnnotation: "clusterissuer",
			}),
			ExpectedName: "clusterissuer",
			ExpectedKind: "ClusterIssuer",
		},
		{
			Ingress: buildIngress("name", "namespace", map[string]string{
				testAcmeTLSAnnotation: "true",
			}),
			DefaultName:  "default-name",
			DefaultKind:  "ClusterIssuer",
			ExpectedName: "default-name",
			ExpectedKind: "ClusterIssuer",
		},
		{
			Ingress: buildIngress("name", "namespace", nil),
		},
	}
	for _, test := range tests {
		c := &Controller{
			defaults: defaults{
				issuerKind: test.DefaultKind,
				issuerName: test.DefaultName,
			},
		}
		name, kind := c.issuerForIngress(test.Ingress)
		if name != test.ExpectedName {
			t.Errorf("expected name to be %q but got %q", test.ExpectedName, name)
		}
		if kind != test.ExpectedKind {
			t.Errorf("expected kind to be %q but got %q", test.ExpectedKind, kind)
		}
	}
}

func buildCertificate(name, namespace string) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

func buildACMEIssuer(name, namespace string) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				ACME: &v1alpha1.ACMEIssuer{},
			},
		},
	}
}

func buildIngress(name, namespace string, annotations map[string]string) *extv1beta1.Ingress {
	return &extv1beta1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
		},
	}
}
