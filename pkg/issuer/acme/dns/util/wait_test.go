package util

import (
	"reflect"
	"sort"
	"strings"
	"testing"
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
	{"physics.georgetown.edu.",
		[]string{"ns1.georgetown.edu.", "ns2.georgetown.edu.", "ns3.georgetown.edu."},
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
	{"8.8.8.8.asn.routeviews.org.", "151698.8.8.024", []string{"asnums.routeviews.org."},
		true,
	},
	// No TXT RR
	{"ns1.google.com.", "", []string{"ns2.google.com."},
		false,
	},
	// TXT RR /w unexpected value
	{"8.8.8.8.asn.routeviews.org.", "fe01=", []string{"asnums.routeviews.org."},
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
	{"testdata/resolv.conf.nonexistant", []string{"127.0.0.1:53"}, []string{"127.0.0.1:53"}},
}

func TestPreCheckDNS(t *testing.T) {
	// TODO: find a better TXT record to use in tests
	ok, err := PreCheckDNS("google.com.", "v=spf1 include:_spf.google.com ~all")
	if err != nil || !ok {
		t.Errorf("preCheckDNS failed for acme-staging.api.letsencrypt.org: %s", err.Error())
	}
}

func TestLookupNameserversOK(t *testing.T) {
	for _, tt := range lookupNameserversTestsOK {
		nss, err := lookupNameservers(tt.fqdn)
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
		_, err := lookupNameservers(tt.fqdn)
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
