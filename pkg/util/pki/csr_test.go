package pki

import (
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func buildCertificate(cn string, dnsNames ...string) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		Spec: v1alpha1.CertificateSpec{
			CommonName: cn,
			DNSNames:   dnsNames,
		},
	}
}

func TestCommonNameForCertificate(t *testing.T) {
	type testT struct {
		name        string
		crtCN       string
		crtDNSNames []string
		expectedCN  string
		expectErr   bool
	}
	tests := []testT{
		{
			name:       "certificate with CommonName set",
			crtCN:      "test",
			expectedCN: "test",
		},
		{
			name:        "certificate with one DNS name set",
			crtDNSNames: []string{"dnsname"},
			expectedCN:  "dnsname",
		},
		{
			name:      "certificate with neither common name or dnsNames set",
			expectErr: true,
		},
		{
			name:        "certificate with both common name and dnsName set",
			crtCN:       "cn",
			crtDNSNames: []string{"dnsname"},
			expectedCN:  "cn",
		},
		{
			name:        "certificate with multiple dns names set",
			crtDNSNames: []string{"dnsname1", "dnsname2"},
			expectedCN:  "dnsname1",
		},
	}
	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			actualCN, err := CommonNameForCertificate(buildCertificate(test.crtCN, test.crtDNSNames...))
			if err != nil && !test.expectErr {
				t.Errorf("did not expect error from CommonNameForCertificate: %s", err.Error())
				return
			}
			if actualCN != test.expectedCN {
				t.Errorf("expected %q but got %q", test.expectedCN, actualCN)
				return
			}
		}
	}
	for _, test := range tests {
		t.Run(test.name, testFn(test))
	}
}

func TestDNSNamesForCertificate(t *testing.T) {
	type testT struct {
		name           string
		crtCN          string
		crtDNSNames    []string
		expectDNSNames []string
		expectErr      bool
	}
	tests := []testT{
		{
			name:           "certificate with CommonName set",
			crtCN:          "test",
			expectDNSNames: []string{"test"},
		},
		{
			name:           "certificate with one DNS name set",
			crtDNSNames:    []string{"dnsname"},
			expectDNSNames: []string{"dnsname"},
		},
		{
			name:      "certificate with neither common name or dnsNames set",
			expectErr: true,
		},
		{
			name:           "certificate with both common name and dnsName set",
			crtCN:          "cn",
			crtDNSNames:    []string{"dnsname"},
			expectDNSNames: []string{"cn", "dnsname"},
		},
		{
			name:           "certificate with multiple dns names set",
			crtDNSNames:    []string{"dnsname1", "dnsname2"},
			expectDNSNames: []string{"dnsname1", "dnsname2"},
		},
		{
			name:           "certificate with dnsName[0] set to equal common name",
			crtCN:          "cn",
			crtDNSNames:    []string{"cn", "dnsname"},
			expectDNSNames: []string{"cn", "dnsname"},
		},
		{
			name:           "certificate with a dnsName equal to cn",
			crtCN:          "cn",
			crtDNSNames:    []string{"dnsname", "cn"},
			expectDNSNames: []string{"cn", "dnsname"},
		},
	}
	testFn := func(test testT) func(*testing.T) {
		return func(t *testing.T) {
			actualDNSNames, err := DNSNamesForCertificate(buildCertificate(test.crtCN, test.crtDNSNames...))
			if err != nil && !test.expectErr {
				t.Errorf("did not expect error from CommonNameForCertificate: %s", err.Error())
				return
			}
			if len(actualDNSNames) != len(test.expectDNSNames) {
				t.Errorf("expected %q but got %q", test.expectDNSNames, actualDNSNames)
				return
			}
			for i, actual := range actualDNSNames {
				if test.expectDNSNames[i] != actual {
					t.Errorf("expected %q but got %q", test.expectDNSNames, actualDNSNames)
					return
				}
			}
		}
	}
	for _, test := range tests {
		t.Run(test.name, testFn(test))
	}
}
