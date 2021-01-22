// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package util

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

var lookupNameserversTestsOK = []struct {
	fqdn string
	nss  []string
}{
	{"books.google.com.ng.",
		[]string{"ns1.google.com.", "ns2.google.com.", "ns3.google.com.", "ns4.google.com."},
	},
	{"www.google.com.",
		[]string{"ns1.google.com.", "ns2.google.com.", "ns3.google.com.", "ns4.google.com."},
	},
}

var lookupNameserversTestsErr = []struct {
	fqdn  string
	error string
}{
	// invalid tld
	{"_null.n0n0.",
		"Could not determine the zone",
	},
}

var findZoneByFqdnTests = []struct {
	fqdn string
	zone string
}{
	{"mail.google.com.", "google.com."},             // domain is a CNAME
	{"foo.google.com.", "google.com."},              // domain is a non-existent subdomain
	{"example.com.ac.", "ac."},                      // domain is a eTLD
	{"cross-zone-example.assets.sh.", "assets.sh."}, // domain is a cross-zone CNAME
}

var checkAuthoritativeNssTests = []struct {
	fqdn, value string
	ns          []string
	ok          bool
}{
	// TXT RR w/ expected value
	{"8.8.8.8.asn.routeviews.org.", "151698.8.8.024", []string{"asnums.routeviews.org.:53"},
		true,
	},
	// No TXT RR
	{"ns1.google.com.", "", []string{"ns2.google.com.:53"},
		false,
	},
	// TXT RR /w unexpected value
	{"8.8.8.8.asn.routeviews.org.", "fe01=", []string{"asnums.routeviews.org.:53"},
		false,
	},
}

var checkAuthoritativeNssTestsErr = []struct {
	fqdn, value string
	ns          []string
	error       string
}{
	// invalid nameserver
	{"8.8.8.8.asn.routeviews.org.", "fe01=", []string{"invalidns.com."},
		"",
	},
}

var checkResolvConfServersTests = []struct {
	fixture  string
	expected []string
	defaults []string
}{
	{"testdata/resolv.conf.1", []string{"10.200.3.249:53", "10.200.3.250:5353", "[2001:4860:4860::8844]:53", "[10.0.0.1]:5353"}, []string{"127.0.0.1:53"}},
	{"testdata/resolv.conf.nonexistent", []string{"127.0.0.1:53"}, []string{"127.0.0.1:53"}},
}

func TestMatchCAA(t *testing.T) {
	tests := map[string]struct {
		caas       []*dns.CAA
		issuerIDs  map[string]bool
		isWildcard bool
		matches    bool
	}{
		"matches with a single 'issue' caa for a non-wildcard domain": {
			caas:       []*dns.CAA{{Tag: issueTag, Value: "example-ca"}},
			issuerIDs:  map[string]bool{"example-ca": true},
			isWildcard: false,
			matches:    true,
		},
		"matches with a single 'issue' caa for a wildcard domain": {
			caas:       []*dns.CAA{{Tag: issueTag, Value: "example-ca"}},
			issuerIDs:  map[string]bool{"example-ca": true},
			isWildcard: true,
			matches:    true,
		},
		"does not match with a single 'issue' caa for a non-wildcard domain": {
			caas:       []*dns.CAA{{Tag: issueTag, Value: "example-ca"}},
			issuerIDs:  map[string]bool{"not-example-ca": true},
			isWildcard: false,
			matches:    false,
		},
		"matches with a single 'issuewild' caa for a wildcard domain": {
			caas:       []*dns.CAA{{Tag: issuewildTag, Value: "example-ca"}},
			issuerIDs:  map[string]bool{"example-ca": true},
			isWildcard: true,
			matches:    true,
		},
		"does not match with a single 'issuewild' caa for a non-wildcard domain": {
			caas:       []*dns.CAA{{Tag: issuewildTag, Value: "example-ca"}},
			issuerIDs:  map[string]bool{"example-ca": true},
			isWildcard: false,
			matches:    false,
		},
		"still matches if only one of two CAAs does not match issuerID": {
			caas: []*dns.CAA{
				{Tag: issueTag, Value: "not-example-ca"},
				{Tag: issueTag, Value: "example-ca"},
			},
			issuerIDs:  map[string]bool{"example-ca": true},
			isWildcard: false,
			matches:    true,
		},
		"matches with a wildcard name if the wildcard tag permits the CA": {
			caas: []*dns.CAA{
				{Tag: issueTag, Value: "not-example-ca"},
				{Tag: issuewildTag, Value: "example-ca"},
			},
			issuerIDs:  map[string]bool{"example-ca": true},
			isWildcard: true,
			matches:    true,
		},
		"does not match with a wildcard name if the issuewild tag is set and does not match, but an issue tag does": {
			caas: []*dns.CAA{
				{Tag: issueTag, Value: "example-ca"},
				{Tag: issuewildTag, Value: "not-example-ca"},
			},
			issuerIDs:  map[string]bool{"example-ca": true},
			isWildcard: true,
			matches:    false,
		},
	}

	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			m := matchCAA(test.caas, test.issuerIDs, test.isWildcard)
			if test.matches != m {
				t.Errorf("expected match to equal %t but got %t", test.matches, m)
			}
		})
	}
}

func TestPreCheckDNS(t *testing.T) {
	// TODO: find a better TXT record to use in tests
	ok, err := PreCheckDNS("google.com.", "v=spf1 include:_spf.google.com ~all", []string{"8.8.8.8:53"}, true)
	if err != nil || !ok {
		t.Errorf("preCheckDNS failed for acme-staging.api.letsencrypt.org: %s", err.Error())
	}
}

func TestPreCheckDNSNonAuthoritative(t *testing.T) {
	// TODO: find a better TXT record to use in tests
	ok, err := PreCheckDNS("google.com.", "v=spf1 include:_spf.google.com ~all", []string{"1.1.1.1:53"}, false)
	if err != nil || !ok {
		t.Errorf("preCheckDNS failed for acme-staging.api.letsencrypt.org: %s", err.Error())
	}
}

func TestLookupNameserversOK(t *testing.T) {
	for _, tt := range lookupNameserversTestsOK {
		nss, err := lookupNameservers(tt.fqdn, RecursiveNameservers)
		if err != nil {
			t.Fatalf("#%s: got %q; want nil", tt.fqdn, err)
		}

		sort.Strings(nss)
		sort.Strings(tt.nss)

		if !reflect.DeepEqual(nss, tt.nss) {
			t.Errorf("#%s: got %v; want %v", tt.fqdn, nss, tt.nss)
		}
	}
}

func TestLookupNameserversErr(t *testing.T) {
	for _, tt := range lookupNameserversTestsErr {
		_, err := lookupNameservers(tt.fqdn, RecursiveNameservers)
		if err == nil {
			t.Fatalf("#%s: expected %q (error); got <nil>", tt.fqdn, tt.error)
		}

		if !strings.Contains(err.Error(), tt.error) {
			t.Errorf("#%s: expected %q (error); got %q", tt.fqdn, tt.error, err)
			continue
		}
	}
}

func TestFindZoneByFqdn(t *testing.T) {
	for _, tt := range findZoneByFqdnTests {
		res, err := FindZoneByFqdn(tt.fqdn, RecursiveNameservers)
		if err != nil {
			t.Errorf("FindZoneByFqdn failed for %s: %v", tt.fqdn, err)
		}
		if res != tt.zone {
			t.Errorf("%s: got %s; want %s", tt.fqdn, res, tt.zone)
		}
	}
}

func TestCheckAuthoritativeNss(t *testing.T) {
	for _, tt := range checkAuthoritativeNssTests {
		ok, _ := checkAuthoritativeNss(tt.fqdn, tt.value, tt.ns)
		if ok != tt.ok {
			t.Errorf("%s: got %t; want %t", tt.fqdn, ok, tt.ok)
		}
	}
}

func TestCheckAuthoritativeNssErr(t *testing.T) {
	for _, tt := range checkAuthoritativeNssTestsErr {
		_, err := checkAuthoritativeNss(tt.fqdn, tt.value, tt.ns)
		if err == nil {
			t.Fatalf("#%s: expected %q (error); got <nil>", tt.fqdn, tt.error)
		}
		if !strings.Contains(err.Error(), tt.error) {
			t.Errorf("#%s: expected %q (error); got %q", tt.fqdn, tt.error, err)
			continue
		}
	}
}

func TestResolveConfServers(t *testing.T) {
	for _, tt := range checkResolvConfServersTests {
		result := getNameservers(tt.fixture, tt.defaults)

		sort.Strings(result)
		sort.Strings(tt.expected)
		if !reflect.DeepEqual(result, tt.expected) {
			t.Errorf("#%s: expected %q; got %q", tt.fixture, tt.expected, result)
		}
	}
}

// TODO: find a website which uses issuewild?
func TestValidateCAA(t *testing.T) {
	// google installs a CAA record at google.com
	// ask for the www.google.com record to test that
	// we recurse up the labels
	err := ValidateCAA("www.google.com", []string{"letsencrypt", "pki.goog"}, false, RecursiveNameservers)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	// now ask, expecting a CA that won't match
	err = ValidateCAA("www.google.com", []string{"daniel.homebrew.ca"}, false, RecursiveNameservers)
	if err == nil {
		t.Fatalf("expected err, got success")
	}
	// if the CAA record allows non-wildcards then it has an `issue` tag,
	// and it is known that it has no issuewild tags, then wildcard certificates
	// will also be allowed
	err = ValidateCAA("www.google.com", []string{"pki.goog"}, true, RecursiveNameservers)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	// ask for a domain you know does not have CAA records.
	// it should succeed
	err = ValidateCAA("www.example.org", []string{"daniel.homebrew.ca"}, false, RecursiveNameservers)
	if err != nil {
		t.Fatalf("expected err, got %s", err)
	}
}

func Test_followCNAMEs(t *testing.T) {
	dnsQuery = func(fqdn string, rtype uint16, nameservers []string, recursive bool) (in *dns.Msg, err error) {
		msg := &dns.Msg{}
		msg.Rcode = dns.RcodeSuccess
		switch fqdn {
		case "test1.example.com":
			msg.Answer = []dns.RR{
				&dns.CNAME{
					Target: "test2.example.com",
				},
			}
		case "test2.example.com":
			msg.Answer = []dns.RR{
				&dns.CNAME{

					Target: "test3.example.com",
				},
			}
		case "recursive.example.com":
			msg.Answer = []dns.RR{
				&dns.CNAME{

					Target: "recursive1.example.com",
				},
			}
		case "recursive1.example.com":
			msg.Answer = []dns.RR{
				&dns.CNAME{
					Target: "recursive.example.com",
				},
			}
		case "error.example.com":
			return nil, fmt.Errorf("Error while mocking resolve for %q", fqdn)
		}

		// inject fqdn in headers
		for _, rr := range msg.Answer {
			if cn, ok := rr.(*dns.CNAME); ok {
				cn.Hdr = dns.RR_Header{
					Name: fqdn,
				}
			}
		}

		return msg, nil
	}
	defer func() {
		// restore the mock
		dnsQuery = DNSQuery
	}()
	type args struct {
		fqdn        string
		nameservers []string
		fqdnChain   []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Resolve CNAME 3 down",
			args: args{
				fqdn: "test1.example.com",
			},
			want:    "test3.example.com",
			wantErr: false,
		},
		{
			name: "Resolve CNAME 1 down",
			args: args{
				fqdn: "test3.example.com",
			},
			want:    "test3.example.com",
			wantErr: false,
		},
		{
			name: "Error when DNS fails",
			args: args{
				fqdn: "error.example.com",
			},
			wantErr: true,
		},
		{
			name: "Error on recursive CNAME",
			args: args{
				fqdn: "recursive.example.com",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := followCNAMEs(tt.args.fqdn, tt.args.nameservers, tt.args.fqdnChain...)
			if (err != nil) != tt.wantErr {
				t.Errorf("followCNAMEs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("followCNAMEs() got = %v, want %v", got, tt.want)
			}
		})
	}
}
