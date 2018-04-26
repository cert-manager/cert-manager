package controller

import (
	"reflect"
	"testing"

	extv1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmfake "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
)

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
			Annotations: map[string]string{tlsACMEAnnotation: "true"},
			ShouldSync:  true,
		},
		{
			Annotations: map[string]string{tlsACMEAnnotation: "false"},
			ShouldSync:  false,
		},
		{
			Annotations: map[string]string{tlsACMEAnnotation: ""},
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
		shouldSync := shouldSync(buildIngress("", "", test.Annotations))
		if shouldSync != test.ShouldSync {
			t.Errorf("Expected shouldSync=%v for annotations %#v", test.ShouldSync, test.Annotations)
		}
	}
}

func TestBuildCertificates(t *testing.T) {
	type testT struct {
		Name                string
		Ingress             *extv1beta1.Ingress
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
			Name: "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations using edit-in-place",
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{buildACMEClusterIssuer("issuer-name")},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       "ingress-namespace",
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", "ingress-namespace", nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.ACMECertificateDomainConfig{
								{
									Domains: []string{"example.com", "www.example.com"},
									ACMESolverConfig: v1alpha1.ACMESolverConfig{
										HTTP01: &v1alpha1.ACMECertificateHTTP01Config{
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
			Name: "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations with no ingress class set",
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{buildACMEClusterIssuer("issuer-name")},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       "ingress-namespace",
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", "ingress-namespace", nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.ACMECertificateDomainConfig{
								{
									Domains: []string{"example.com", "www.example.com"},
									ACMESolverConfig: v1alpha1.ACMESolverConfig{
										HTTP01: &v1alpha1.ACMECertificateHTTP01Config{},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name: "return a single HTTP01 Certificate for an ingress with a single valid TLS entry and HTTP01 annotations with a custom ingress class",
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{buildACMEClusterIssuer("issuer-name")},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       "ingress-namespace",
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", "ingress-namespace", nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.ACMECertificateDomainConfig{
								{
									Domains: []string{"example.com", "www.example.com"},
									ACMESolverConfig: v1alpha1.ACMESolverConfig{
										HTTP01: &v1alpha1.ACMECertificateHTTP01Config{
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
			Name: "edit-in-place set to false should not trigger editing the ingress in-place",
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{buildACMEClusterIssuer("issuer-name")},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       "ingress-namespace",
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", "ingress-namespace", nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.ACMECertificateDomainConfig{
								{
									Domains: []string{"example.com", "www.example.com"},
									ACMESolverConfig: v1alpha1.ACMESolverConfig{
										HTTP01: &v1alpha1.ACMECertificateHTTP01Config{
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
			Name: "should error when an ingress specifies dns01 challenge type but no challenge provider",
			Err:  true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{buildACMEClusterIssuer("issuer-name")},
		},
		{
			Name: "should error when an invalid ACME challenge type is specified",
			Err:  true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{buildACMEClusterIssuer("issuer-name")},
		},
		{
			Name: "return a single DNS01 Certificate for an ingress with a single valid TLS entry and DNS01 annotations",
			Err:  true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{buildACMEClusterIssuer("issuer-name")},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       "ingress-namespace",
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", "ingress-namespace", nil), ingressGVK)},
					},
					Spec: v1alpha1.CertificateSpec{
						DNSNames:   []string{"example.com", "www.example.com"},
						SecretName: "example-com-tls",
						IssuerRef: v1alpha1.ObjectReference{
							Name: "issuer-name",
							Kind: "ClusterIssuer",
						},
						ACME: &v1alpha1.ACMECertificateConfig{
							Config: []v1alpha1.ACMECertificateDomainConfig{
								{
									Domains: []string{"example.com", "www.example.com"},
									ACMESolverConfig: v1alpha1.ACMESolverConfig{
										DNS01: &v1alpha1.ACMECertificateDNS01Config{
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
			Name: "should error when no challenge type is provided",
			Err:  true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{buildACMEClusterIssuer("issuer-name")},
		},
		{
			Name:              "should return a basic certificate when no provider specific config is provided",
			DefaultIssuerName: "issuer-name",
			DefaultIssuerKind: "ClusterIssuer",
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{buildClusterIssuer("issuer-name")},
			ExpectedCreate: []*v1alpha1.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-com-tls",
						Namespace:       "ingress-namespace",
						OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(buildIngress("ingress-name", "ingress-namespace", nil), ingressGVK)},
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
			Name: "should return an error when no TLS hosts are specified",
			Err:  true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			IssuerLister: []*v1alpha1.Issuer{buildACMEIssuer("issuer-name", "ingress-namespace")},
		},
		{
			Name: "should return an error when no TLS secret name is specified",
			Err:  true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			IssuerLister: []*v1alpha1.Issuer{buildACMEIssuer("issuer-name", "ingress-namespace")},
		},
		{
			Name: "should error if the specified issuer is not found",
			Err:  true,
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
					Annotations: map[string]string{
						issuerNameAnnotation: "invalid-issuer-name",
					},
				},
			},
		},
		{
			Name: "should not return any certificates if a correct Certificate already exists",
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			IssuerLister: []*v1alpha1.Issuer{buildACMEIssuer("issuer-name", "ingress-namespace")},
			CertificateLister: []*v1alpha1.Certificate{
				&v1alpha1.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-crt",
						Namespace: "ingress-namespace",
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
		},
		{
			Name: "should update a certificate if an incorrect Certificate exists",
			Ingress: &extv1beta1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-name",
					Namespace: "ingress-namespace",
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
			IssuerLister:      []*v1alpha1.Issuer{buildACMEIssuer("issuer-name", "ingress-namespace")},
			CertificateLister: []*v1alpha1.Certificate{buildCertificate("existing-crt", "ingress-namespace")},
			ExpectedUpdate: []*v1alpha1.Certificate{
				&v1alpha1.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-crt",
						Namespace: "ingress-namespace",
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
			createCrts, updateCrts, err := c.buildCertificates(test.Ingress)
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
				tlsACMEAnnotation: "true",
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

func TestGetGenericIssuer(t *testing.T) {
	var nilIssuer *v1alpha1.Issuer
	var nilClusterIssuer *v1alpha1.ClusterIssuer
	type testT struct {
		Name                   string
		Kind                   string
		Namespace              string
		IssuerLister           []*v1alpha1.Issuer
		ClusterIssuerLister    []*v1alpha1.ClusterIssuer
		NilClusterIssuerLister bool
		Err                    bool
		Expected               v1alpha1.GenericIssuer
	}
	tests := []testT{
		{
			Name:         "name",
			Kind:         "Issuer",
			Namespace:    "namespace",
			IssuerLister: []*v1alpha1.Issuer{buildIssuer("name", "namespace")},
			Expected:     buildIssuer("name", "namespace"),
		},
		{
			Name:                "name",
			Kind:                "ClusterIssuer",
			ClusterIssuerLister: []*v1alpha1.ClusterIssuer{buildClusterIssuer("name")},
			Expected:            buildClusterIssuer("name"),
		},
		{
			Name:     "name",
			Kind:     "Issuer",
			Err:      true,
			Expected: nilIssuer,
		},
		{
			Name:     "name",
			Kind:     "ClusterIssuer",
			Err:      true,
			Expected: nilClusterIssuer,
		},
		{
			Name: "name",
			Err:  true,
		},
		{
			Name: "name",
			Kind: "ClusterIssuer",
			NilClusterIssuerLister: true,
			Err: true,
		},
	}

	for _, test := range tests {
		cmClient := cmfake.NewSimpleClientset()
		factory := cminformers.NewSharedInformerFactory(cmClient, 0)
		issuerInformer := factory.Certmanager().V1alpha1().Issuers()
		clusterIssuerInformer := factory.Certmanager().V1alpha1().ClusterIssuers()
		for _, i := range test.IssuerLister {
			issuerInformer.Informer().GetIndexer().Add(i)
		}
		for _, i := range test.ClusterIssuerLister {
			clusterIssuerInformer.Informer().GetIndexer().Add(i)
		}
		c := &Controller{
			issuerLister:        issuerInformer.Lister(),
			clusterIssuerLister: clusterIssuerInformer.Lister(),
		}
		if test.NilClusterIssuerLister {
			c.clusterIssuerLister = nil
		}
		actual, err := c.getGenericIssuer(test.Namespace, test.Name, test.Kind)
		if err != nil && !test.Err {
			t.Errorf("Expected no error, but got: %s", err)
			continue
		}
		if !reflect.DeepEqual(actual, test.Expected) {
			t.Errorf("Expected %#v but got %#v", test.Expected, actual)
		}
	}
}

func buildIssuer(name, namespace string) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
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

func buildACMEClusterIssuer(name string) *v1alpha1.ClusterIssuer {
	return &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				ACME: &v1alpha1.ACMEIssuer{},
			},
		},
	}
}

func buildClusterIssuer(name string) *v1alpha1.ClusterIssuer {
	return &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
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
