package acme

import (
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/third_party/crypto/acme"
)

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
