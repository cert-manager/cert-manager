package acme

import (
	"context"
	"fmt"
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/client"
	"github.com/jetstack/cert-manager/test/util/generate"
	"github.com/jetstack/cert-manager/third_party/crypto/acme"
)

const (
	defaultTestNamespace = "default"
)

func TestGetOrCreateOrder(t *testing.T) {
	issuer := generate.Issuer(generate.IssuerConfig{
		Name:               "test",
		Namespace:          defaultTestNamespace,
		HTTP01:             &v1alpha1.ACMEIssuerHTTP01Config{},
		ACMEServer:         "fakeserver",
		ACMEEmail:          "fakeemail",
		ACMEPrivateKeyName: "fakeprivkey",
	})
	certificate := generate.Certificate(generate.CertificateConfig{
		Name:         "test-crt",
		Namespace:    defaultTestNamespace,
		IssuerName:   issuer.Name,
		IssuerKind:   issuer.Kind,
		DNSNames:     []string{"example.com"},
		ACMEOrderURL: "",
	})
	invalidOrderURL := "invalidorderurl"
	validOrderURL := "validorderurl"

	tests := map[string]acmeFixture{
		"should call createOrder if order URL is blank": acmeFixture{
			Issuer: issuer,
			PreFn: func(a *acmeFixture) {
				crt, err := a.f.CertManagerClient().CertmanagerV1alpha1().Certificates(defaultTestNamespace).Create(certificate)
				if err != nil {
					t.Errorf("Error preparing test: %v", err)
					t.FailNow()
				}
				a.Certificate = crt
			},
			Client: &client.FakeACME{
				FakeCreateOrder: func(_ context.Context, order *acme.Order) (*acme.Order, error) {
					order.URL = validOrderURL
					return order, nil
				},
			},
			CheckFn: func(a *acmeFixture, args ...interface{}) {
				order := args[0].(*acme.Order)
				if order.URL != validOrderURL {
					t.Errorf("Expected order URL to be set to %q, but it is %q", validOrderURL, order.URL)
				}
				if a.Certificate.Status.ACME.Order.URL != validOrderURL {
					t.Errorf("Expected certificate acme order url to be set to %q but it was %q", validOrderURL, a.Certificate.Status.ACME.Order.URL)
				}
			},
		},
		"should return an error if GetOrder returns an error": acmeFixture{
			Issuer: issuer,
			Err:    true,
			PreFn: func(a *acmeFixture) {
				t := a.f.T
				crt := certificate.DeepCopy()
				crt.Status.ACME.Order.URL = validOrderURL
				crt, err := a.f.CertManagerClient().CertmanagerV1alpha1().Certificates(defaultTestNamespace).Create(crt)
				if err != nil {
					t.Errorf("Error preparing test: %v", err)
					t.FailNow()
				}
				a.Certificate = crt
			},
			Client: &client.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acme.Order, error) {
					return nil, fmt.Errorf("fake error")
				},
			},
			CheckFn: func(a *acmeFixture, args ...interface{}) {
				t := a.f.T
				order := args[0].(*acme.Order)
				if order != nil {
					t.Errorf("expected order to be nil")
				}
			},
		},
		"should return existing order if it's pending": acmeFixture{
			Issuer: issuer,
			PreFn: func(a *acmeFixture) {
				t := a.f.T
				crt := certificate.DeepCopy()
				crt.Status.ACME.Order.URL = validOrderURL
				crt, err := a.f.CertManagerClient().CertmanagerV1alpha1().Certificates(defaultTestNamespace).Create(crt)
				if err != nil {
					t.Errorf("Error preparing test: %v", err)
					t.FailNow()
				}
				a.Certificate = crt
			},
			Client: &client.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acme.Order, error) {
					// we call buildOrder to ensure the dns names are correctly set
					order := acme.NewOrder("example.com")
					order.URL = url
					order.Status = acme.StatusPending
					return order, nil
				},
			},
			CheckFn: func(a *acmeFixture, args ...interface{}) {
				t := a.f.T
				order := args[0].(*acme.Order)
				if len(order.Identifiers) != 1 {
					t.Errorf("expected one identifier, but identifiers=%+v", order.Identifiers)
					t.Fail()
				}
				if order.Identifiers[0].Value != "example.com" {
					t.Errorf("expected identifier to be 'example.com' but it is %q", order.Identifiers[0].Value)
				}
				if order.Status != acme.StatusPending {
					t.Errorf("expected order status to be pending, but it is %q", order.Status)
				}
			},
		},
		"should create a new order if existing order is failed": acmeFixture{
			Issuer: issuer,
			PreFn: func(a *acmeFixture) {
				t := a.f.T
				crt := certificate.DeepCopy()
				crt.Status.ACME.Order.URL = validOrderURL
				crt, err := a.f.CertManagerClient().CertmanagerV1alpha1().Certificates(defaultTestNamespace).Create(crt)
				if err != nil {
					t.Errorf("Error preparing test: %v", err)
					t.FailNow()
				}
				a.Certificate = crt
			},
			Client: &client.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acme.Order, error) {
					// we call buildOrder to ensure the dns names are correctly set
					order := acme.NewOrder("example.com")
					order.URL = url
					order.Status = acme.StatusInvalid
					return order, nil
				},
				FakeCreateOrder: func(_ context.Context, order *acme.Order) (*acme.Order, error) {
					order.URL = validOrderURL
					return order, nil
				},
			},
			CheckFn: func(a *acmeFixture, args ...interface{}) {
				t := a.f.T
				order := args[0].(*acme.Order)
				if len(order.Identifiers) != 1 {
					t.Errorf("expected one identifier, but identifiers=%+v", order.Identifiers)
					t.Fail()
				}
				if order.Identifiers[0].Value != "example.com" {
					t.Errorf("expected identifier to be 'example.com' but it is %q", order.Identifiers[0].Value)
				}
				if order.Status == acme.StatusInvalid {
					t.Errorf("expected order status to not be invalid")
				}
			},
		},
		"should create a new order if existing order is for a different set of dns names": acmeFixture{
			Issuer: issuer,
			PreFn: func(a *acmeFixture) {
				t := a.f.T
				crt := certificate.DeepCopy()
				crt.Status.ACME.Order.URL = invalidOrderURL
				crt, err := a.f.CertManagerClient().CertmanagerV1alpha1().Certificates(defaultTestNamespace).Create(crt)
				if err != nil {
					t.Errorf("Error preparing test: %v", err)
					t.FailNow()
				}
				a.Certificate = crt
			},
			Client: &client.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acme.Order, error) {
					// we call buildOrder to ensure the dns names are correctly set
					order := acme.NewOrder("notexample.com")
					// todo: assert that this url = invalidOrderURL
					order.URL = url
					order.Status = acme.StatusPending
					return order, nil
				},
				FakeCreateOrder: func(_ context.Context, order *acme.Order) (*acme.Order, error) {
					order.URL = validOrderURL
					return order, nil
				},
			},
			CheckFn: func(a *acmeFixture, args ...interface{}) {
				t := a.f.T
				order := args[0].(*acme.Order)
				if len(order.Identifiers) != 1 {
					t.Errorf("expected one identifier, but identifiers=%+v", order.Identifiers)
					t.Fail()
				}
				if order.Identifiers[0].Value != "example.com" {
					t.Errorf("expected identifier to be 'example.com' but it is %q", order.Identifiers[0].Value)
				}
				if a.Certificate.Status.ACME.Order.URL != validOrderURL {
					t.Errorf("expected certificate order url status field to be %q but it is %q", validOrderURL, a.Certificate.Status.ACME.Order.URL)
				}
			},
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			test.Setup(t)
			defer test.f.Stop()
			order, err := test.Acme.getOrCreateOrder(test.Ctx, test.Client, test.Certificate)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
				t.FailNow()
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
				t.FailNow()
			}
			test.Finish(t, order, err)
		})
	}
}

func TestPickChallengeType(t *testing.T) {
	type testT struct {
		Domain            string
		OfferedChallenges []string
		CertConfigs       []v1alpha1.ACMECertificateDomainConfig
		ACMEIssuer        v1alpha1.ACMEIssuer

		ExpectedType string
		Error        bool
	}
	tests := map[string]testT{
		"correctly selects http01 validation": {
			Domain:            "example.com",
			OfferedChallenges: []string{"http-01"},
			CertConfigs: []v1alpha1.ACMECertificateDomainConfig{
				{
					Domains: []string{"example.com"},
					HTTP01:  &v1alpha1.ACMECertificateHTTP01Config{},
				},
			},
			ACMEIssuer: v1alpha1.ACMEIssuer{
				HTTP01: &v1alpha1.ACMEIssuerHTTP01Config{},
			},
			ExpectedType: "http-01",
		},
		"selects http01 challenge type and ignores the configured dns01 provider": {
			Domain:            "example.com",
			OfferedChallenges: []string{"http-01", "dns-01"},
			CertConfigs: []v1alpha1.ACMECertificateDomainConfig{
				{
					Domains: []string{"www.example.com"},
					DNS01:   &v1alpha1.ACMECertificateDNS01Config{},
				},
				{
					Domains: []string{"example.com"},
					HTTP01:  &v1alpha1.ACMECertificateHTTP01Config{},
				},
			},
			ACMEIssuer: v1alpha1.ACMEIssuer{
				DNS01:  &v1alpha1.ACMEIssuerDNS01Config{},
				HTTP01: &v1alpha1.ACMEIssuerHTTP01Config{},
			},
			ExpectedType: "http-01",
		},
		"correctly selects dns01 challenge type": {
			Domain:            "www.example.com",
			OfferedChallenges: []string{"http-01", "dns-01"},
			CertConfigs: []v1alpha1.ACMECertificateDomainConfig{
				{
					Domains: []string{"www.example.com"},
					DNS01:   &v1alpha1.ACMECertificateDNS01Config{},
				},
				{
					Domains: []string{"example.com"},
					HTTP01:  &v1alpha1.ACMECertificateHTTP01Config{},
				},
			},
			ACMEIssuer: v1alpha1.ACMEIssuer{
				DNS01:  &v1alpha1.ACMEIssuerDNS01Config{},
				HTTP01: &v1alpha1.ACMEIssuerHTTP01Config{},
			},
			ExpectedType: "dns-01",
		},
		"error if none of the offered challenges are configured on the issuer": {
			Domain:            "example.com",
			OfferedChallenges: []string{"http-01", "dns-01"},
			CertConfigs: []v1alpha1.ACMECertificateDomainConfig{
				{
					Domains: []string{"example.com"},
					HTTP01:  &v1alpha1.ACMECertificateHTTP01Config{},
				},
			},
			ACMEIssuer: v1alpha1.ACMEIssuer{},
			Error:      true,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			a := &Acme{issuer: &v1alpha1.Issuer{Spec: v1alpha1.IssuerSpec{
				IssuerConfig: v1alpha1.IssuerConfig{
					ACME: &test.ACMEIssuer,
				},
			}}}
			challenges := make([]*acme.Challenge, len(test.OfferedChallenges))
			for i, c := range test.OfferedChallenges {
				challenges[i] = &acme.Challenge{Type: c}
			}
			acmeAuthz := &acme.Authorization{Challenges: challenges}
			pickedType, err := a.pickChallengeType(test.Domain, acmeAuthz, test.CertConfigs)
			if err != nil && !test.Error {
				t.Errorf("Error picking ACME challenge type, but no error was expected: %v", err)
				t.Fail()
			}
			if err == nil && test.Error {
				t.Errorf("Expected an error picking ACME challenge type, but instead got a type: %q", pickedType)
				t.Fail()
			}
			if pickedType != test.ExpectedType {
				t.Errorf("Expected picked type to be %q but it was instead %q", test.ExpectedType, pickedType)
			}
		})
	}
}
