//go:build !livedns_test

// +skip_license_check

package util

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type input struct {
	query   string
	domains []string
}

type test struct {
	name      string
	input     input
	want, got string
}

var domains = []string{
	"foo.example.com",
	"foo.bar.example.com",
	"example.com",
	"baz.com",
}

var tests = []*test{
	{
		name: "TestExactMatchTLD",
		input: input{
			query:   "example.com",
			domains: domains,
		},
		want: "example.com",
	},
	{
		name: "TestExactMatchSubDomain",
		input: input{
			query:   "foo.example.com",
			domains: domains,
		},
		want: "foo.example.com",
	},
	{
		name: "TestExactMatchSubDomainTwoLevels",
		input: input{
			query:   "foo.bar.example.com",
			domains: domains,
		},
		want: "foo.bar.example.com",
	},
	{
		name: "TestPartialMatchTLD",
		input: input{
			query:   "baz.example.com",
			domains: domains,
		},
		want: "example.com",
	},
	{
		name: "TestPartialMatchSubDomain",
		input: input{
			query:   "baz.foo.example.com",
			domains: domains,
		},
		want: "foo.example.com",
	},
	{
		name: "TestNoMatchReversedOrder", // Negative Test Case
		input: input{
			query:   "com.example.foo",
			domains: domains,
		},
		want: "",
	},
	{
		name: "TestNoMatches", // Negative Test Case
		input: input{
			query:   "bar.com",
			domains: domains,
		},
		want: "",
	},
}

func TestLongestMatches(t *testing.T) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.got, _ = FindBestMatch(tc.input.query, tc.input.domains...)
			if tc.got != tc.want {
				assert.Equal(t, tc.want, tc.got, fmt.Sprintf("Failed: TestCase: %s | Query: %s | Want: %v | Got: %v", tc.name, tc.input.query, tc.want, tc.got))
			}
		})
	}
}

func TestDNS01LookupFQDN_WildcardCNAME(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		follow   bool
		mockDNS  []interaction
		wantFQDN string
		wantErr  bool
	}{
		{
			// When a wildcard CNAME exists on the parent domain (e.g.,
			// *.monitoring.example.com -> monitoring.westeurope.cloudapp.azure.com),
			// querying _acme-challenge.monitoring.example.com will return the
			// wildcard's target. We should NOT follow this CNAME.
			name:     "wildcard CNAME on parent domain should not be followed",
			domain:   "monitoring.example.com",
			follow:   true,
			wantFQDN: "_acme-challenge.monitoring.example.com.",
			mockDNS: []interaction{
				// First query: CNAME lookup for the challenge subdomain.
				// DNS returns the wildcard's target because *.monitoring.example.com exists.
				{"CNAME _acme-challenge.monitoring.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "_acme-challenge.monitoring.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "monitoring.westeurope.cloudapp.azure.com.",
						},
					},
				}},
				// Second query: CNAME lookup for the wildcard on the parent domain.
				// This confirms the CNAME is from a wildcard record.
				{"CNAME *.monitoring.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "*.monitoring.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "monitoring.westeurope.cloudapp.azure.com.",
						},
					},
				}},
			},
		},
		{
			// When an explicit CNAME is set on _acme-challenge.example.com
			// (intentional DNS-01 delegation), it should be followed as before.
			name:     "explicit CNAME on _acme-challenge should be followed",
			domain:   "example.com",
			follow:   true,
			wantFQDN: "_acme-challenge.delegated.example.net.",
			mockDNS: []interaction{
				// isWildcardCNAME: query CNAME for _acme-challenge.example.com.
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "_acme-challenge.delegated.example.net.",
						},
					},
				}},
				// isWildcardCNAME: query CNAME for *.example.com.
				// No wildcard exists, so this returns NXDOMAIN.
				{"CNAME *.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				// followCNAMEs: follows the explicit CNAME chain.
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "_acme-challenge.delegated.example.net.",
						},
					},
				}},
				// followCNAMEs: no further CNAME on the target.
				{"CNAME _acme-challenge.delegated.example.net.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
		},
		{
			// When no CNAME record exists at all, the FQDN should be
			// returned unchanged.
			name:     "no CNAME record should return original FQDN",
			domain:   "example.com",
			follow:   true,
			wantFQDN: "_acme-challenge.example.com.",
			mockDNS: []interaction{
				// isWildcardCNAME: query CNAME for _acme-challenge.example.com.
				// No CNAME exists.
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
				// followCNAMEs: also finds no CNAME.
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
		},
		{
			// When followCNAME is false, no CNAME resolution should happen.
			name:     "followCNAME disabled should skip CNAME resolution",
			domain:   "example.com",
			follow:   false,
			wantFQDN: "_acme-challenge.example.com.",
			mockDNS:  []interaction{},
		},
		{
			// When a wildcard CNAME exists but the _acme-challenge subdomain has
			// a different explicit CNAME (overriding the wildcard), it should be
			// followed.
			name:     "explicit CNAME different from wildcard should be followed",
			domain:   "monitoring.example.com",
			follow:   true,
			wantFQDN: "_acme-challenge.dns-validation.example.net.",
			mockDNS: []interaction{
				// isWildcardCNAME: query CNAME for _acme-challenge.monitoring.example.com.
				{"CNAME _acme-challenge.monitoring.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "_acme-challenge.monitoring.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "_acme-challenge.dns-validation.example.net.",
						},
					},
				}},
				// isWildcardCNAME: query CNAME for *.monitoring.example.com.
				// Wildcard exists but points to a different target.
				{"CNAME *.monitoring.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "*.monitoring.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "monitoring.westeurope.cloudapp.azure.com.",
						},
					},
				}},
				// followCNAMEs: follows the explicit CNAME.
				{"CNAME _acme-challenge.monitoring.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "_acme-challenge.monitoring.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "_acme-challenge.dns-validation.example.net.",
						},
					},
				}},
				// followCNAMEs: no further CNAME on the target.
				{"CNAME _acme-challenge.dns-validation.example.net.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withMockDNSQuery(t, tc.mockDNS)
			got, err := DNS01LookupFQDN(t.Context(), tc.domain, tc.follow, "not-used")
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantFQDN, got)
		})
	}
}
