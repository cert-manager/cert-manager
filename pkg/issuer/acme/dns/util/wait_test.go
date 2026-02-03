//go:build !livedns_test

// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package util

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupNameserversOK(t *testing.T) {
	tests := []struct {
		givenFQDN string
		expectNSs []string
		mockDNS   []interaction // Key example: "SOA en.wikipedia.org."
	}{
		{
			givenFQDN: "en.wikipedia.org.",
			mockDNS: []interaction{
				{"SOA en.wikipedia.org.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "en.wikipedia.org.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 13213}, Target: "dyna.wikimedia.org."},
					},
					Ns: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "wikimedia.org.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 400}, Ns: "ns0.wikimedia.org.", Mbox: "hostmaster.wikimedia.org.", Serial: 2025050119, Refresh: 43200, Retry: 7200, Expire: 1209600, Minttl: 600},
					},
				}},
				{"SOA wikipedia.org.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "wikipedia.org.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 2920}, Ns: "ns0.wikimedia.org.", Mbox: "hostmaster.wikimedia.org.", Serial: 2025032815, Refresh: 43200, Retry: 7200, Expire: 1209600, Minttl: 3600},
					},
				}},
				{"NS wikipedia.org.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.NS{Hdr: dns.RR_Header{Name: "wikipedia.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 86297}, Ns: "ns1.wikimedia.org."},
						&dns.NS{Hdr: dns.RR_Header{Name: "wikipedia.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 86297}, Ns: "ns2.wikimedia.org."},
						&dns.NS{Hdr: dns.RR_Header{Name: "wikipedia.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 86297}, Ns: "ns0.wikimedia.org."},
					},
				}},
			},
			expectNSs: []string{"ns0.wikimedia.org.", "ns1.wikimedia.org.", "ns2.wikimedia.org."},
		},
		{
			givenFQDN: "www.google.com.",
			mockDNS: []interaction{
				{"SOA www.google.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Ns: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 6}, Ns: "ns1.google.com.", Mbox: "dns-admin.google.com.", Serial: 754576681, Refresh: 900, Retry: 900, Expire: 1800, Minttl: 60},
					},
				}},
				{"SOA google.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.google.com.", Mbox: "dns-admin.google.com.", Serial: 754576681, Refresh: 900, Retry: 900, Expire: 1800, Minttl: 60},
					},
				}},
				{"NS google.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.NS{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 73176}, Ns: "ns4.google.com."},
						&dns.NS{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 73176}, Ns: "ns2.google.com."},
						&dns.NS{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 73176}, Ns: "ns1.google.com."},
						&dns.NS{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 73176}, Ns: "ns3.google.com."},
					},
				}},
			},
			expectNSs: []string{"ns1.google.com.", "ns2.google.com.", "ns3.google.com.", "ns4.google.com."},
		},
		{
			givenFQDN: "physics.georgetown.edu.",
			mockDNS: []interaction{
				{"SOA physics.georgetown.edu.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "physics.georgetown.edu.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.b1ddi.physics.georgetown.edu.", Mbox: "ncs-sm.georgetown.edu.", Serial: 2011022637, Refresh: 10800, Retry: 3600, Expire: 2419200, Minttl: 300},
					},
				}},
				{"NS physics.georgetown.edu.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.NS{Hdr: dns.RR_Header{Name: "physics.georgetown.edu.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 196}, Ns: "ns4.georgetown.edu."},
						&dns.NS{Hdr: dns.RR_Header{Name: "physics.georgetown.edu.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 196}, Ns: "ns.b1ddi.physics.georgetown.edu."},
						&dns.NS{Hdr: dns.RR_Header{Name: "physics.georgetown.edu.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 196}, Ns: "ns6.georgetown.edu."},
						&dns.NS{Hdr: dns.RR_Header{Name: "physics.georgetown.edu.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 196}, Ns: "ns5.georgetown.edu."},
					},
				}},
			},
			expectNSs: []string{"ns.b1ddi.physics.georgetown.edu.", "ns4.georgetown.edu.", "ns5.georgetown.edu.", "ns6.georgetown.edu."},
		},
	}

	for _, tc := range tests {
		t.Run(tc.givenFQDN, func(t *testing.T) {
			withMockDNSQuery(t, tc.mockDNS)
			nss, err := lookupNameservers(t.Context(), tc.givenFQDN, []string{"not-used"})
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.expectNSs, nss, "Expected nameservers do not match")
		})
	}
}

func TestLookupNameserversErr(t *testing.T) {
	t.Run("no SOA record can be found", func(t *testing.T) {
		withMockDNSQuery(t, []interaction{
			{"SOA _null.n0n0.", &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Ns: []dns.RR{
					&dns.SOA{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 2655}, Ns: "a.root-servers.net.", Mbox: "nstld.verisign-grs.com.", Serial: 2025050500, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 86400},
				},
			}},
			{"SOA n0n0.", &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Ns: []dns.RR{
					&dns.SOA{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 2664}, Ns: "a.root-servers.net.", Mbox: "nstld.verisign-grs.com.", Serial: 2025050500, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 86400},
				},
			}},
		})
		_, err := lookupNameservers(t.Context(), "_null.n0n0.", []string{"not-used"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Could not determine the zone")
	})
}

func TestFindZoneByFqdn(t *testing.T) {
	tests := []struct {
		givenFQDN  string
		mockDNS    []interaction
		expectZone string
	}{
		{
			// In this test, we make sure that we are able to recurse up to
			// google.com given that it is a CNAME that points to
			// googlemail.l.google.com. Data from 2021-04-17:
			// https://dnsviz.net/d/mail.google.com/YHtmLQ/responses/
			givenFQDN:  "mail.google.com.",
			expectZone: "google.com.",
			mockDNS: []interaction{
				{"SOA mail.google.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "mail.google.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 604800}, Target: "googlemail.l.google.com."},
					},
					Ns: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.google.com.", Mbox: "dns-admin.google.com.", Serial: 754990191, Refresh: 900, Retry: 900, Expire: 1800, Minttl: 60},
					},
				}},
				{"SOA google.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 32}, Ns: "ns1.google.com.", Mbox: "dns-admin.google.com.", Serial: 754990191, Refresh: 900, Retry: 900, Expire: 1800, Minttl: 60},
					},
				}},
			},
		},
		{
			// This test checks that we do not return SOA records that are not a
			// suffix of the domain. In the below test, the SOA RR `example.com`
			// must be ignored. We detect such a case by ignoring SOA that are
			// returned alongside CNAME records. This is a consequence of RFC
			// 2181 that states that CNAME records cannot exist at the root of a
			// zone. See: https://github.com/go-acme/lego/pull/449.
			givenFQDN:  "cross-zone-example.assets.sh.",
			expectZone: "assets.sh.",
			mockDNS: []interaction{
				{"SOA cross-zone-example.assets.sh.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "cross-zone-example.assets.sh.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "example.com."},
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 2633}, Ns: "ns.icann.org.", Mbox: "noc.dns.icann.org.", Serial: 2025011636, Refresh: 7200, Retry: 3600, Expire: 1209600, Minttl: 3600},
					},
				}},
				{"SOA assets.sh.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "assets.sh.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 979}, Ns: "gina.ns.cloudflare.com.", Mbox: "dns.cloudflare.com.", Serial: 2371821451, Refresh: 10000, Retry: 2400, Expire: 604800, Minttl: 1800},
					},
				}},
			},
		},
		{
			// This test shows that FindZoneByFqdn can work is able to continue
			// climbing up the tree when a non-existent domain is found. We do
			// this because the `_acme-challenge` subdomain may not exist yet,
			// but we still want to find the zone for the domain.
			givenFQDN:  "nonexistent.cert-manager.io.",
			expectZone: "cert-manager.io.",
			mockDNS: []interaction{
				{"SOA nonexistent.cert-manager.io.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}, // NXDOMAIN
					Ns: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "cert-manager.io.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 21}, Ns: "ns-cloud-a1.googledomains.com.", Mbox: "cloud-dns-hostmaster.google.com.", Serial: 2, Refresh: 21600, Retry: 3600, Expire: 259200, Minttl: 300},
					},
				}},
				{"SOA cert-manager.io.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "cert-manager.io.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 31}, Ns: "ns-cloud-a1.googledomains.com.", Mbox: "cloud-dns-hostmaster.google.com.", Serial: 2, Refresh: 21600, Retry: 3600, Expire: 259200, Minttl: 300},
					},
				}},
			},
		},
		{
			// This test shows that FindZoneByFqdn works with eTLD domains
			// (effective top-level domain).
			givenFQDN:  "example.com.ac.",
			expectZone: "ac.",
			mockDNS: []interaction{
				{"SOA example.com.ac.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}, // NXDOMAIN
					Ns: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "ac.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3500}, Ns: "a0.nic.ac", Mbox: "hostmaster.donuts.email", Serial: 1746448794, Refresh: 7200, Retry: 900, Expire: 1209600, Minttl: 3600},
					},
				}},
				{"SOA com.ac.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}, // NXDOMAIN
					Ns: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "ac.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3496}, Ns: "a0.nic.ac", Mbox: "hostmaster.donuts.email", Serial: 1746448794, Refresh: 7200, Retry: 900, Expire: 1209600, Minttl: 3600},
					},
				}},
				{"SOA ac.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "ac.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3486}, Ns: "a0.nic.ac", Mbox: "hostmaster.donuts.email", Serial: 1746448794, Refresh: 7200, Retry: 900, Expire: 1209600, Minttl: 3600},
					},
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.givenFQDN, func(t *testing.T) {
			withMockDNSQuery(t, tt.mockDNS)
			gotZone, err := FindZoneByFqdn(t.Context(), tt.givenFQDN, []string{"not-used"})
			require.NoError(t, err)
			assert.Equal(t, tt.expectZone, gotZone)
		})
	}
}

func TestCheckAuthoritativeNss(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		withMockDNSQuery(t, []interaction{
			{"TXT 8.8.8.8.asn.routeviews.org.", &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.TXT{Hdr: dns.RR_Header{Name: "8.8.8.8.asn.routeviews.org.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"fe01="}},
				},
			}},
		})
		ok, err := checkAuthoritativeNss(t.Context(), "8.8.8.8.asn.routeviews.org.", "fe01=", []string{"1.1.1.1:53"})
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("TXT not found", func(t *testing.T) {
		withMockDNSQuery(t, []interaction{
			{"TXT 8.8.8.8.asn.routeviews.org.", &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
			}},
		})
		ok, err := checkAuthoritativeNss(t.Context(), "8.8.8.8.asn.routeviews.org.", "fe01=", []string{"1.1.1.1:53"})
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("errors out when DnsQuery fails", func(t *testing.T) {
		withMockDNSQueryErr(t, fmt.Errorf("some error coming from DnsQuery"))

		_, err := checkAuthoritativeNss(t.Context(), "8.8.8.8.asn.routeviews.org.", "fe01=", []string{"1.1.1.1:53"})
		assert.EqualError(t, err, "some error coming from DnsQuery")
	})
}

// These tests don't require mocking out dnsQuery as getNameservers doesn't rely
// on it.
func TestResolveConfServers(t *testing.T) {
	checkResolvConfServersTests := []struct {
		fixture  string
		expected []string
		defaults []string
	}{
		{"testdata/resolv.conf.1", []string{"10.200.3.249:53", "10.200.3.250:5353", "[2001:4860:4860::8844]:53", "[10.0.0.1]:5353"}, []string{"127.0.0.1:53"}},
		{"testdata/resolv.conf.nonexistent", []string{"127.0.0.1:53"}, []string{"127.0.0.1:53"}},
	}
	for _, tt := range checkResolvConfServersTests {
		result := getNameservers(tt.fixture, tt.defaults)

		sort.Strings(result)
		sort.Strings(tt.expected)
		if !reflect.DeepEqual(result, tt.expected) {
			t.Errorf("#%s: expected %q; got %q", tt.fixture, tt.expected, result)
		}
	}
}

func TestDNS01LookupFQDN(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		followCNAME bool
		mockDNS     []interaction
		expected    string
		wantErr     bool
	}{
		{
			name:        "no CNAME following",
			domain:      "example.com",
			followCNAME: false,
			mockDNS:     []interaction{},
			expected:    "_acme-challenge.example.com.",
			wantErr:     false,
		},
		{
			name:        "explicit CNAME to same zone - should follow",
			domain:      "example.com",
			followCNAME: true,
			mockDNS: []interaction{
				// FindZoneByFqdn for original domain
				{"SOA example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
				// followCNAMEs
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "_acme-challenge.delegated.example.com."},
					},
				}},
				{"CNAME _acme-challenge.delegated.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
				// FindZoneByFqdn for resolved FQDN
				{"SOA _acme-challenge.delegated.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"SOA delegated.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"SOA example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
			},
			expected: "_acme-challenge.delegated.example.com.",
			wantErr:  false,
		},
		{
			name:        "explicit CNAME to subdomain zone - should follow",
			domain:      "example.com",
			followCNAME: true,
			mockDNS: []interaction{
				// FindZoneByFqdn for original domain
				{"SOA example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
				// followCNAMEs
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "_acme-challenge.acme.example.com."},
					},
				}},
				{"CNAME _acme-challenge.acme.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
				// FindZoneByFqdn for resolved FQDN
				{"SOA _acme-challenge.acme.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"SOA acme.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "acme.example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
			},
			expected: "_acme-challenge.acme.example.com.",
			wantErr:  false,
		},
		{
			name:        "wildcard CNAME to unrelated zone - should fall back",
			domain:      "monitoring.example.com",
			followCNAME: true,
			mockDNS: []interaction{
				// FindZoneByFqdn for original domain
				{"SOA monitoring.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"SOA example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
				// followCNAMEs - wildcard *.monitoring.example.com matches
				{"CNAME _acme-challenge.monitoring.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "_acme-challenge.monitoring.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "_acme-challenge.monitoring.westeurope.cloudapp.azure.com."},
					},
				}},
				{"CNAME _acme-challenge.monitoring.westeurope.cloudapp.azure.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
				// FindZoneByFqdn for resolved FQDN - finds azure.com zone
				{"SOA _acme-challenge.monitoring.westeurope.cloudapp.azure.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"SOA monitoring.westeurope.cloudapp.azure.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"SOA westeurope.cloudapp.azure.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"SOA cloudapp.azure.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"SOA azure.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "azure.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
			},
			expected: "_acme-challenge.monitoring.example.com.", // Falls back to original
			wantErr:  false,
		},
		{
			name:        "no CNAME present - use original",
			domain:      "example.com",
			followCNAME: true,
			mockDNS: []interaction{
				// FindZoneByFqdn for original domain
				{"SOA example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
				// followCNAMEs - no CNAME found
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
			expected: "_acme-challenge.example.com.",
			wantErr:  false,
		},
		{
			name:        "cannot find zone for resolved FQDN - fall back",
			domain:      "example.com",
			followCNAME: true,
			mockDNS: []interaction{
				// FindZoneByFqdn for original domain
				{"SOA example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
				// followCNAMEs
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "_acme-challenge.nonexistent.invalid."},
					},
				}},
				{"CNAME _acme-challenge.nonexistent.invalid.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
				// FindZoneByFqdn for resolved FQDN - fails
				{"SOA _acme-challenge.nonexistent.invalid.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"SOA nonexistent.invalid.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"SOA invalid.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
			},
			expected: "_acme-challenge.example.com.", // Falls back to original
			wantErr:  false,
		},
		{
			name:        "cannot find zone for original domain - fall back without CNAME following",
			domain:      "nonexistent.invalid",
			followCNAME: true,
			mockDNS: []interaction{
				// FindZoneByFqdn for original domain - fails
				{"SOA nonexistent.invalid.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"SOA invalid.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
			},
			expected: "_acme-challenge.nonexistent.invalid.",
			wantErr:  false,
		},
		{
			name:        "CNAME loop detection - should error",
			domain:      "example.com",
			followCNAME: true,
			mockDNS: []interaction{
				// FindZoneByFqdn for original domain
				{"SOA example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
				// followCNAMEs - loop
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "_acme-challenge.loop.example.com."},
					},
				}},
				{"CNAME _acme-challenge.loop.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "_acme-challenge.loop.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "_acme-challenge.example.com."},
					},
				}},
			},
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear the zone cache before each test
			fqdnToZoneLock.Lock()
			fqdnToZone = map[string]cachedEntry{}
			fqdnToZoneLock.Unlock()

			withMockDNSQuery(t, tt.mockDNS)
			result, err := DNS01LookupFQDN(t.Context(), tt.domain, tt.followCNAME, "not-used")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_followCNAMEs(t *testing.T) {
	type args struct {
		fqdn        string
		nameservers []string
		fqdnChain   []string
	}
	tests := []struct {
		name    string
		mock    []interaction
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Resolve CNAME 3 down",
			args: args{
				fqdn: "test1.example.com.",
			},
			want:    "test3.example.com.",
			wantErr: false,
			mock: []interaction{
				{"CNAME test1.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "test1.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "test2.example.com."},
					},
				}},
				{"CNAME test2.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "test2.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "test3.example.com."},
					},
				}},
				{"CNAME test3.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
		},
		{
			name: "Resolve CNAME 1 down",
			args: args{
				fqdn: "test3.example.com.",
			},
			want:    "test3.example.com.",
			wantErr: false,
			mock: []interaction{
				{"CNAME test3.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
		},
		{
			name: "Error on recursive CNAME",
			args: args{
				fqdn: "recursive.example.com.",
			},
			wantErr: true,
			mock: []interaction{
				{"CNAME recursive.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "recursive.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "recursive1.example.com."},
					},
				}},
				{"CNAME recursive1.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "recursive1.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "recursive.example.com."},
					},
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withMockDNSQuery(t, tt.mock)
			got, err := followCNAMEs(t.Context(), tt.args.fqdn, tt.args.nameservers, tt.args.fqdnChain...)
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

type interaction struct {
	expectedQuery string // E.g., "SOA en.wikipedia.org."
	mockAnswer    *dns.Msg
}

var mu = &sync.Mutex{} // Protects the global dnsQuery variable.

func withMockDNSQuery(t *testing.T, mockDNS []interaction) {
	mu.Lock()
	t.Cleanup(func() {
		mu.Unlock()
	})

	// Since dnsQuery is a global variable, we need to save its original value
	// and restore it after the test.
	origDNSQuery := dnsQuery
	t.Cleanup(func() { dnsQuery = origDNSQuery })

	count := atomic.Int32{}
	t.Cleanup(func() {
		assert.Equal(t, len(mockDNS), int(count.Load()), "not all DNS queries were called")
	})

	dnsQuery = func(ctx context.Context, fqdn string, rtype uint16, nameservers []string, recursive bool) (in *dns.Msg, err error) {
		got := dns.TypeToString[rtype] + " " + fqdn

		count.Add(1)
		if int(count.Load()) > len(mockDNS) {
			t.Fatalf("too many DNS queries, was expecting %d queries but got %d. The unexpected query is: %s", len(mockDNS), count.Load(), got)
		}

		mock := mockDNS[count.Load()-1]
		assert.Equal(t, mock.expectedQuery, got, "DNS query doesn't match the expected query #%d", count.Load())
		return mock.mockAnswer.Copy().SetQuestion(fqdn, rtype), nil
	}
}

// Same as above except it simulates an error.
func withMockDNSQueryErr(t *testing.T, err error) {
	mu.Lock()
	t.Cleanup(func() {
		mu.Unlock()
	})

	// Since dnsQuery is a global variable, we need to save its original value
	// and restore it after the test.
	origDNSQuery := dnsQuery
	t.Cleanup(func() { dnsQuery = origDNSQuery })

	dnsQuery = func(ctx context.Context, fqdn string, rtype uint16, nameservers []string, recursive bool) (in *dns.Msg, err2 error) {
		return nil, err
	}
}
