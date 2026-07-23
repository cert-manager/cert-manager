// The unit tests in this file mock the global dnsQuery variable and share
// helper types with wait_test.go, which is also excluded under this tag.
//go:build !livedns_test

// +skip_license_check

package util

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file contains code adapted from a contribution sent by Oleh Konko as part of GHSA-gx3x-vq4p-mhhv

func TestCachingResolver_FindZoneByFQDN(t *testing.T) {
	tests := []struct {
		name       string
		givenFQDN  string
		mockDNS    []interaction
		expectZone string
		expectErr  string
	}{
		{
			name:       "NXDOMAIN: climbs to zone apex",
			givenFQDN:  "sub.example.com.",
			expectZone: "example.com.",
			mockDNS: []interaction{
				{"SOA sub.example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
				{"SOA example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
			},
		},
		{
			// Per RFC 2181, CNAME cannot exist at a zone apex, so a SOA alongside a
			// CNAME is not authoritative for that label. The search continues up the tree.
			name:       "CNAME at label is skipped per RFC 2181",
			givenFQDN:  "sub.example.com.",
			expectZone: "example.com.",
			mockDNS: []interaction{
				{"SOA sub.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "sub.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "other.com."},
					},
				}},
				{"SOA example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
			},
		},
		{
			name:      "SERVFAIL stops the search and returns an error",
			givenFQDN: "sub.example.com.",
			expectErr: "When querying the SOA record for the domain 'sub.example.com.' using nameservers [not-used], rcode was expected to be 'NOERROR' or 'NXDOMAIN', but got 'SERVFAIL'",
			mockDNS: []interaction{
				{"SOA sub.example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}},
			},
		},
		{
			name:      "no SOA found anywhere in the tree returns error",
			givenFQDN: "sub.example.com.",
			expectErr: "Could not find the SOA record in the DNS tree for the domain 'sub.example.com.' using nameservers [not-used]",
			mockDNS: []interaction{
				{"SOA sub.example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
				{"SOA example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
				{"SOA com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withMockDNSQuery(t, tt.mockDNS)
			c := CachingResolver{}
			gotZone, err := c.FindZoneByFQDN(t.Context(), tt.givenFQDN, []string{"not-used"})
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectZone, gotZone)
		})
	}
}

func TestCachingResolver_CacheHit(t *testing.T) {
	fqdn := "sub.example.com."

	// Exactly two DNS queries for the first call. withMockDNSQuery fails the test
	// if any further queries are made, so a cache hit on the second call is verified
	// implicitly.
	withMockDNSQuery(t, []interaction{
		{"SOA sub.example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
		{"SOA example.com.", &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{
				&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
			},
		}},
	})

	c := CachingResolver{}

	zone, err := c.FindZoneByFQDN(t.Context(), fqdn, []string{"ns1:53"})
	require.NoError(t, err)
	assert.Equal(t, "example.com.", zone)

	zone, err = c.FindZoneByFQDN(t.Context(), fqdn, []string{"ns1:53"})
	require.NoError(t, err)
	assert.Equal(t, "example.com.", zone)
}

func TestCachingResolver_CacheExpiry(t *testing.T) {
	fqdn := "sub.example.com."
	nxDomain := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	// TTL=0 means the cache entry expires at the moment it is written, so any
	// subsequent call sees it as stale and re-queries.
	soaTTL0 := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Answer: []dns.RR{
			&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0}},
		},
	}

	// Both calls make DNS queries because the cache entry expires immediately.
	withMockDNSQuery(t, []interaction{
		{"SOA sub.example.com.", nxDomain},
		{"SOA example.com.", soaTTL0},
		{"SOA sub.example.com.", nxDomain},
		{"SOA example.com.", soaTTL0},
	})

	c := CachingResolver{}

	zone, err := c.FindZoneByFQDN(t.Context(), fqdn, []string{"ns1:53"})
	require.NoError(t, err)
	assert.Equal(t, "example.com.", zone)

	zone, err = c.FindZoneByFQDN(t.Context(), fqdn, []string{"ns1:53"})
	require.NoError(t, err)
	assert.Equal(t, "example.com.", zone)
}

// TestCachingResolver_NameserverFallthrough verifies that a query error from one
// nameserver does not abort the search: the next nameserver is tried instead.
func TestCachingResolver_NameserverFallthrough(t *testing.T) {
	ns1, ns2 := "ns1:53", "ns2:53"
	fqdn := "sub.example.com."

	mu.Lock()
	t.Cleanup(func() { mu.Unlock() })
	orig := dnsQuery
	t.Cleanup(func() { dnsQuery = orig })

	var callCount atomic.Int32
	dnsQuery = func(_ context.Context, _ string, _ uint16, nameservers []string, _ bool) (*dns.Msg, error) {
		n := int(callCount.Add(1))
		switch n {
		case 1:
			assert.Equal(t, []string{ns1}, nameservers)
			return nil, fmt.Errorf("ns1 unreachable")
		case 2:
			assert.Equal(t, []string{ns2}, nameservers)
			return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}, nil
		case 3:
			assert.Equal(t, []string{ns2}, nameservers)
			return &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{
					&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
				},
			}, nil
		default:
			t.Fatalf("unexpected DNS query #%d", n)
			return nil, nil
		}
	}

	c := CachingResolver{}
	zone, err := c.FindZoneByFQDN(t.Context(), fqdn, []string{ns1, ns2})
	require.NoError(t, err)
	assert.Equal(t, "example.com.", zone)
	assert.Equal(t, int32(3), callCount.Load())
}

func TestCachingResolver_AllNameserversFail(t *testing.T) {
	withMockDNSQueryErr(t, fmt.Errorf("nameserver unreachable"))

	c := CachingResolver{}
	_, err := c.FindZoneByFQDN(t.Context(), "sub.example.com.", []string{"ns1:53", "ns2:53"})
	require.EqualError(t, err, "nameserver unreachable")
}

// TestCachingResolver_PerNameserverCaching verifies that cache entries are keyed per
// nameserver: querying ns1 and ns2 independently populates separate entries,
// and a subsequent call with [ns1, ns2] returns ns1's cached result without
// querying ns2.
func TestCachingResolver_PerNameserverCaching(t *testing.T) {
	fqdn := "sub.example.com."
	ns1, ns2 := "ns1:53", "ns2:53"
	nxDomain := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	soaResp := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Answer: []dns.RR{
			&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
		},
	}

	// ns1 and ns2 each require two queries; the third call with [ns1, ns2] uses
	// ns1's cache entry and makes no additional queries.
	withMockDNSQuery(t, []interaction{
		{"SOA sub.example.com.", nxDomain},
		{"SOA example.com.", soaResp},
		{"SOA sub.example.com.", nxDomain},
		{"SOA example.com.", soaResp},
	})

	c := CachingResolver{}

	zone, err := c.FindZoneByFQDN(t.Context(), fqdn, []string{ns1})
	require.NoError(t, err)
	assert.Equal(t, "example.com.", zone)

	zone, err = c.FindZoneByFQDN(t.Context(), fqdn, []string{ns2})
	require.NoError(t, err)
	assert.Equal(t, "example.com.", zone)

	// ns1 is first in the list and cached; ns2 is never queried.
	zone, err = c.FindZoneByFQDN(t.Context(), fqdn, []string{ns1, ns2})
	require.NoError(t, err)
	assert.Equal(t, "example.com.", zone)
}

// TestCachingResolver_ZeroValue confirms that the zero value CachingResolver{} is safe to
// use without explicit initialisation (the internal map is lazily allocated).
func TestCachingResolver_ZeroValue(t *testing.T) {
	withMockDNSQuery(t, []interaction{
		{"SOA example.com.", &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{
				&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
			},
		}},
	})

	var c CachingResolver
	_, err := c.FindZoneByFQDN(t.Context(), "example.com.", []string{"ns1:53"})
	require.NoError(t, err)
}

func TestCachingResolver_Clean(t *testing.T) {
	now := time.Now()
	c := &CachingResolver{
		cache: map[cacheKey]cacheEntry{
			{Nameserver: "ns1:53", FQDN: "expired.example.com."}: {
				Response: &dns.Msg{},
				Expiry:   now.Add(-time.Minute),
			},
			{Nameserver: "ns1:53", FQDN: "valid.example.com."}: {
				Response: &dns.Msg{},
				Expiry:   now.Add(time.Hour),
			},
		},
	}

	c.clean(t.Context())

	c.mu.RLock()
	defer c.mu.RUnlock()
	_, hasExpired := c.cache[cacheKey{Nameserver: "ns1:53", FQDN: "expired.example.com."}]
	_, hasValid := c.cache[cacheKey{Nameserver: "ns1:53", FQDN: "valid.example.com."}]

	assert.False(t, hasExpired, "expired entry should have been removed")
	assert.True(t, hasValid, "valid entry should be kept")
}

// TestCachingResolver_NoPanic mirrors Test_FindZoneByFqdn_NoPanic for CachingResolver:
// a cached response where the SOA is not at Answer[0] must not panic.
func TestCachingResolver_NoPanic(t *testing.T) {
	zone := "example.com."
	fqdn := fmt.Sprintf("zonecache.%s", zone)

	ns, stop := startDNS(t, zone)
	defer stop()

	c := CachingResolver{}

	_, err := c.FindZoneByFQDN(t.Context(), fqdn, []string{ns})
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on second call: %v", r)
		}
	}()

	_, err = c.FindZoneByFQDN(t.Context(), fqdn, []string{ns})
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
}

func TestCachingResolver_LookupAuthoritativeNameservers(t *testing.T) {
	tests := []struct {
		name      string
		givenFQDN string
		mockDNS   []interaction
		expectNSs []string
		expectErr string
	}{
		{
			// A CNAME in the Answer section causes the SOA search to continue to
			// the parent label, where the real SOA is found (RFC 2181).
			name:      "CNAME at label: zone found at parent",
			givenFQDN: "en.wikipedia.org.",
			mockDNS: []interaction{
				{"SOA en.wikipedia.org.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "en.wikipedia.org.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "dyna.wikimedia.org."},
					},
				}},
				{"SOA wikipedia.org.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "wikipedia.org.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
				{"NS wikipedia.org.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.NS{Hdr: dns.RR_Header{Name: "wikipedia.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.wikimedia.org."},
						&dns.NS{Hdr: dns.RR_Header{Name: "wikipedia.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns2.wikimedia.org."},
						&dns.NS{Hdr: dns.RR_Header{Name: "wikipedia.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns0.wikimedia.org."},
					},
				}},
			},
			expectNSs: []string{"ns0.wikimedia.org.", "ns1.wikimedia.org.", "ns2.wikimedia.org."},
		},
		{
			// SOA in the first response's Ns section (not Answer) means no SOA is
			// found at www.google.com; the search continues to google.com.
			name:      "SOA only in authority section: zone found at parent",
			givenFQDN: "www.google.com.",
			mockDNS: []interaction{
				{"SOA www.google.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				}},
				{"SOA google.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}},
					},
				}},
				{"NS google.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.NS{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.google.com."},
						&dns.NS{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns2.google.com."},
						&dns.NS{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns3.google.com."},
						&dns.NS{Hdr: dns.RR_Header{Name: "google.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns4.google.com."},
					},
				}},
			},
			expectNSs: []string{"ns1.google.com.", "ns2.google.com.", "ns3.google.com.", "ns4.google.com."},
		},
		{
			// SOA is found directly at the queried label.
			name:      "SOA at queried label",
			givenFQDN: "physics.georgetown.edu.",
			mockDNS: []interaction{
				{"SOA physics.georgetown.edu.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "physics.georgetown.edu.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
				{"NS physics.georgetown.edu.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.NS{Hdr: dns.RR_Header{Name: "physics.georgetown.edu.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns4.georgetown.edu."},
						&dns.NS{Hdr: dns.RR_Header{Name: "physics.georgetown.edu.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns5.georgetown.edu."},
						&dns.NS{Hdr: dns.RR_Header{Name: "physics.georgetown.edu.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns6.georgetown.edu."},
					},
				}},
			},
			expectNSs: []string{"ns4.georgetown.edu.", "ns5.georgetown.edu.", "ns6.georgetown.edu."},
		},
		{
			// No SOA record can be found.
			name:      "zone not found returns error",
			givenFQDN: "example.com.",
			mockDNS: []interaction{
				{"SOA example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
				{"SOA com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
			},
			expectErr: `Could not determine the zone for "example.com.": Could not find the SOA record in the DNS tree for the domain 'example.com.' using nameservers [not-used]`,
		},
		{
			name:      "no NS records in response returns error",
			givenFQDN: "example.com.",
			mockDNS: []interaction{
				{"SOA example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
				{"NS example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}},
			},
			expectErr: `Could not determine authoritative nameservers for "example.com."`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withMockDNSQuery(t, tt.mockDNS)
			c := CachingResolver{}
			gotNSs, err := c.LookupAuthoritativeNameservers(t.Context(), tt.givenFQDN, []string{"not-used"})
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.expectNSs, gotNSs)
		})
	}
}

func TestCachingResolver_LookupAuthoritativeNameservers_CacheHit(t *testing.T) {
	// First call makes 3 DNS queries; withMockDNSQuery fails the test on any
	// additional query, so a cache hit on the second call is verified implicitly.
	withMockDNSQuery(t, []interaction{
		{"SOA sub.example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
		{"SOA example.com.", &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{
				&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
			},
		}},
		{"NS example.com.", &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{
				&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.com."},
			},
		}},
	})

	c := CachingResolver{}

	nss, err := c.LookupAuthoritativeNameservers(t.Context(), "sub.example.com.", []string{"ns1:53"})
	require.NoError(t, err)
	assert.Equal(t, []string{"ns1.example.com."}, nss)

	nss, err = c.LookupAuthoritativeNameservers(t.Context(), "sub.example.com.", []string{"ns1:53"})
	require.NoError(t, err)
	assert.Equal(t, []string{"ns1.example.com."}, nss)
}

func TestCachingResolver_LookupAuthoritativeNameservers_AllNameserversFail(t *testing.T) {
	withMockDNSQueryErr(t, fmt.Errorf("nameserver unreachable"))

	c := CachingResolver{}
	_, err := c.LookupAuthoritativeNameservers(t.Context(), "sub.example.com.", []string{"ns1:53"})
	require.EqualError(t, err, `Could not determine the zone for "sub.example.com.": nameserver unreachable`)
}

func TestCachingResolver_CheckTXTRecordPropagation(t *testing.T) {
	tests := []struct {
		name             string
		givenFQDN        string
		givenValue       string
		useAuthoritative bool
		mockDNS          []interaction
		expectFound      bool
		expectErr        string
	}{
		{
			name:             "TXT found, useAuthoritative=false",
			givenFQDN:        "example.com.",
			givenValue:       "token123",
			useAuthoritative: false,
			mockDNS: []interaction{
				{"CNAME example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}},
				{"TXT example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"token123"}},
					},
				}},
			},
			expectFound: true,
		},
		{
			name:             "TXT not found (NXDOMAIN), useAuthoritative=false",
			givenFQDN:        "example.com.",
			givenValue:       "token123",
			useAuthoritative: false,
			mockDNS: []interaction{
				{"CNAME example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}},
				{"TXT example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
			},
			expectFound: false,
		},
		{
			name:             "TXT value mismatch, useAuthoritative=false",
			givenFQDN:        "example.com.",
			givenValue:       "token123",
			useAuthoritative: false,
			mockDNS: []interaction{
				{"CNAME example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}},
				{"TXT example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"wrong-token"}},
					},
				}},
			},
			expectFound: false,
		},
		{
			// followCNAMEs resolves the target FQDN before the TXT check.
			name:             "follows CNAME before checking TXT",
			givenFQDN:        "alias.example.com.",
			givenValue:       "token123",
			useAuthoritative: false,
			mockDNS: []interaction{
				{"CNAME alias.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "real.example.com."},
					},
				}},
				{"CNAME real.example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}},
				{"TXT real.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.TXT{Hdr: dns.RR_Header{Name: "real.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"token123"}},
					},
				}},
			},
			expectFound: true,
		},
		{
			// useAuthoritative=true: resolves NS via SOA lookup, then queries those servers.
			name:             "TXT found via authoritative nameservers",
			givenFQDN:        "example.com.",
			givenValue:       "token123",
			useAuthoritative: true,
			mockDNS: []interaction{
				// followCNAMEs
				{"CNAME example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}},
				// LookupAuthoritativeNameservers -> FindZoneByFQDN
				{"SOA example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}},
					},
				}},
				// LookupAuthoritativeNameservers -> NS query
				{"NS example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.com."},
					},
				}},
				// checkTXTRecord querying the resolved authoritative server
				{"TXT example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"token123"}},
					},
				}},
			},
			expectFound: true,
		},
		{
			name:             "error from authoritative NS lookup propagates",
			givenFQDN:        "example.com.",
			givenValue:       "token123",
			useAuthoritative: true,
			mockDNS: []interaction{
				// followCNAMEs
				{"CNAME example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}},
				// FindZoneByFQDN - no SOA anywhere in tree
				{"SOA example.com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
				{"SOA com.", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}},
			},
			expectErr: `Could not determine the zone for "example.com.": Could not find the SOA record in the DNS tree for the domain 'example.com.' using nameservers [not-used]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withMockDNSQuery(t, tt.mockDNS)
			c := CachingResolver{}
			found, err := c.CheckTXTRecordPropagation(t.Context(), tt.givenFQDN, tt.givenValue, []string{"not-used"}, UseAuthoritative(tt.useAuthoritative))
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectFound, found)
		})
	}
}
