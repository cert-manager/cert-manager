package acme

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSValidServerResponse(t *testing.T) {
	PreCheckDNS = func(fqdn, value string) (bool, error) {
		return true, nil
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Replay-Nonce", "12345")

		_, err = w.Write([]byte("{\"type\":\"dns01\",\"status\":\"valid\",\"uri\":\"http://some.url\",\"token\":\"http8\"}"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))

	go func() {
		time.Sleep(time.Second * 2)
		f := bufio.NewWriter(os.Stdout)
		defer f.Flush()
		_, _ = f.WriteString("\n")
	}()

	manualProvider, err := NewDNSProviderManual()
	require.NoError(t, err)

	clientChallenge := challenge{Type: "dns01", Status: "pending", URL: ts.URL, Token: "http8"}

	solver := &dnsChallenge{
		jws:      &jws{privKey: privKey, getNonceURL: ts.URL},
		validate: validate,
		provider: manualProvider,
	}

	err = solver.Solve(clientChallenge, "example.com")
	require.NoError(t, err)
}

func TestPreCheckDNS(t *testing.T) {
	ok, err := PreCheckDNS("acme-staging.api.letsencrypt.org", "fe01=")
	if err != nil || !ok {
		t.Errorf("PreCheckDNS failed for acme-staging.api.letsencrypt.org")
	}
}

func TestLookupNameserversOK(t *testing.T) {
	testCases := []struct {
		fqdn string
		nss  []string
	}{
		{
			fqdn: "books.google.com.ng.",
			nss:  []string{"ns1.google.com.", "ns2.google.com.", "ns3.google.com.", "ns4.google.com."},
		},
		{
			fqdn: "www.google.com.",
			nss:  []string{"ns1.google.com.", "ns2.google.com.", "ns3.google.com.", "ns4.google.com."},
		},
		{
			fqdn: "physics.georgetown.edu.",
			nss:  []string{"ns1.georgetown.edu.", "ns2.georgetown.edu.", "ns3.georgetown.edu."},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.fqdn, func(t *testing.T) {
			t.Parallel()

			nss, err := lookupNameservers(test.fqdn)
			require.NoError(t, err)

			sort.Strings(nss)
			sort.Strings(test.nss)

			assert.EqualValues(t, test.nss, nss)
		})
	}
}

func TestLookupNameserversErr(t *testing.T) {
	testCases := []struct {
		desc  string
		fqdn  string
		error string
	}{
		{
			desc:  "invalid tld",
			fqdn:  "_null.n0n0.",
			error: "could not determine the zone",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			_, err := lookupNameservers(test.fqdn)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.error)
		})
	}
}

func TestFindZoneByFqdn(t *testing.T) {
	testCases := []struct {
		desc string
		fqdn string
		zone string
	}{
		{
			desc: "domain is a CNAME",
			fqdn: "mail.google.com.",
			zone: "google.com.",
		},
		{
			desc: "domain is a non-existent subdomain",
			fqdn: "foo.google.com.",
			zone: "google.com.",
		},
		{
			desc: "domain is a eTLD",
			fqdn: "example.com.ac.",
			zone: "ac.",
		},
		{
			desc: "domain is a cross-zone CNAME",
			fqdn: "cross-zone-example.assets.sh.",
			zone: "assets.sh.",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			zone, err := FindZoneByFqdn(test.fqdn, RecursiveNameservers)
			require.NoError(t, err)

			assert.Equal(t, test.zone, zone)
		})
	}
}

func TestCheckAuthoritativeNss(t *testing.T) {
	testCases := []struct {
		desc        string
		fqdn, value string
		ns          []string
		expected    bool
	}{
		{
			desc:     "TXT RR w/ expected value",
			fqdn:     "8.8.8.8.asn.routeviews.org.",
			value:    "151698.8.8.024",
			ns:       []string{"asnums.routeviews.org."},
			expected: true,
		},
		{
			desc: "No TXT RR",
			fqdn: "ns1.google.com.",
			ns:   []string{"ns2.google.com."},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			ok, _ := checkAuthoritativeNss(test.fqdn, test.value, test.ns)
			assert.Equal(t, test.expected, ok, test.fqdn)
		})
	}
}

func TestCheckAuthoritativeNssErr(t *testing.T) {
	testCases := []struct {
		desc        string
		fqdn, value string
		ns          []string
		error       string
	}{
		{
			desc:  "TXT RR /w unexpected value",
			fqdn:  "8.8.8.8.asn.routeviews.org.",
			value: "fe01=",
			ns:    []string{"asnums.routeviews.org."},
			error: "did not return the expected TXT record",
		},
		{
			desc:  "No TXT RR",
			fqdn:  "ns1.google.com.",
			value: "fe01=",
			ns:    []string{"ns2.google.com."},
			error: "did not return the expected TXT record",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			_, err := checkAuthoritativeNss(test.fqdn, test.value, test.ns)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.error)
		})
	}
}

func TestResolveConfServers(t *testing.T) {
	var testCases = []struct {
		fixture  string
		expected []string
		defaults []string
	}{
		{
			fixture:  "testdata/resolv.conf.1",
			defaults: []string{"127.0.0.1:53"},
			expected: []string{"10.200.3.249:53", "10.200.3.250:5353", "[2001:4860:4860::8844]:53", "[10.0.0.1]:5353"},
		},
		{
			fixture:  "testdata/resolv.conf.nonexistant",
			defaults: []string{"127.0.0.1:53"},
			expected: []string{"127.0.0.1:53"},
		},
	}

	for _, test := range testCases {
		t.Run(test.fixture, func(t *testing.T) {

			result := getNameservers(test.fixture, test.defaults)

			sort.Strings(result)
			sort.Strings(test.expected)

			assert.Equal(t, test.expected, result)
		})
	}
}

func TestToFqdn(t *testing.T) {
	testCases := []struct {
		desc     string
		domain   string
		expected string
	}{
		{
			desc:     "simple",
			domain:   "foo.bar.com",
			expected: "foo.bar.com.",
		},
		{
			desc:     "already FQDN",
			domain:   "foo.bar.com.",
			expected: "foo.bar.com.",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			fqdn := ToFqdn(test.domain)
			assert.Equal(t, test.expected, fqdn)
		})
	}
}

func TestUnFqdn(t *testing.T) {
	testCases := []struct {
		desc     string
		fqdn     string
		expected string
	}{
		{
			desc:     "simple",
			fqdn:     "foo.bar.com.",
			expected: "foo.bar.com",
		},
		{
			desc:     "already domain",
			fqdn:     "foo.bar.com",
			expected: "foo.bar.com",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			domain := UnFqdn(test.fqdn)

			assert.Equal(t, test.expected, domain)
		})
	}
}
