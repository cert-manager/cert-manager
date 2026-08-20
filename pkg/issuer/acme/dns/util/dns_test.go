//go:build !livedns_test

// +skip_license_check

package util

import (
	"errors"
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
		name    string
		domain  string
		follow  bool
		mockDNS []interaction
		// failQuery, when set, makes that one query return failErr instead of
		// consuming an entry from mockDNS.
		failQuery string
		failErr   error
		wantFQDN  string
		wantErr   bool
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
			// DNS names compare case-insensitively, and the two answers need
			// not preserve the same case.
			name:     "wildcard CNAME differing only in case should not be followed",
			domain:   "monitoring.example.com",
			follow:   true,
			wantFQDN: "_acme-challenge.monitoring.example.com.",
			mockDNS: []interaction{
				{"CNAME _acme-challenge.monitoring.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "_acme-challenge.monitoring.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "Monitoring.WestEurope.CloudApp.Azure.Com.",
						},
					},
				}},
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
			// The first hop is resolved by DNS01LookupFQDN itself and reused, so
			// the challenge name is only queried once.
			name:     "explicit CNAME on _acme-challenge should be followed",
			domain:   "example.com",
			follow:   true,
			wantFQDN: "_acme-challenge.delegated.example.net.",
			mockDNS: []interaction{
				// Query the CNAME for _acme-challenge.example.com.
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
				// followCNAMEs: continues from the already resolved first hop.
				{"CNAME _acme-challenge.delegated.example.net.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
		},
		{
			// A recursive resolver may return the whole chased chain in the
			// answer section, in any order. Only the record owned by the queried
			// name gives the next hop; picking any other record would skip a hop
			// and resolve the wrong chain.
			name:     "chased chain in the challenge answer should not skip a hop",
			domain:   "example.com",
			follow:   true,
			wantFQDN: "b.example.net.",
			mockDNS: []interaction{
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						// Owned by another name; must be skipped even though it
						// comes first in the answer section.
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "a.example.net.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "b.example.net.",
						},
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "a.example.net.",
						},
					},
				}},
				{"CNAME *.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
				}},
				{"CNAME a.example.net.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "a.example.net.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "b.example.net.",
						},
					},
				}},
				{"CNAME b.example.net.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
		},
		{
			// Same for the wildcard probe: if the resolver chases the wildcard's
			// own chain, an intermediate record can share the explicit CNAME's
			// target. Only the record owned by the wildcard name may be compared,
			// otherwise a real delegation is misclassified as synthesized.
			name:     "chased chain in the wildcard answer should not cause a false match",
			domain:   "monitoring.example.com",
			follow:   true,
			wantFQDN: "final.example.net.",
			mockDNS: []interaction{
				{"CNAME _acme-challenge.monitoring.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "_acme-challenge.monitoring.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "final.example.net.",
						},
					},
				}},
				{"CNAME *.monitoring.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						// Chased by the resolver, and it happens to end at the
						// same target as the explicit challenge CNAME. Comparing
						// against this record would wrongly report a wildcard.
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "intermediate.example.net.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "final.example.net.",
						},
						// The wildcard's own target, the only one that may be
						// compared.
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "*.monitoring.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "intermediate.example.net.",
						},
					},
				}},
				{"CNAME final.example.net.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
		},
		{
			// When no CNAME record exists at all, the FQDN should be returned
			// unchanged without probing for a wildcard.
			name:     "no CNAME record should return original FQDN",
			domain:   "example.com",
			follow:   true,
			wantFQDN: "_acme-challenge.example.com.",
			mockDNS: []interaction{
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
		},
		{
			name:     "NXDOMAIN for the challenge name should return original FQDN",
			domain:   "example.com",
			follow:   true,
			wantFQDN: "_acme-challenge.example.com.",
			mockDNS: []interaction{
				{"CNAME _acme-challenge.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
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
				// followCNAMEs: no further CNAME on the target.
				{"CNAME _acme-challenge.dns-validation.example.net.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
		},
		{
			// The wildcard probe is an extra query that cert-manager did not
			// previously make, so a transient failure of it must not break a
			// delegation that used to work.
			name:      "wildcard probe failure should fall back to following the CNAME",
			domain:    "monitoring.example.com",
			follow:    true,
			failQuery: "CNAME *.monitoring.example.com.",
			failErr:   errors.New("simulated network failure"),
			wantFQDN:  "_acme-challenge.dns-validation.example.net.",
			mockDNS: []interaction{
				{"CNAME _acme-challenge.monitoring.example.com.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{
						&dns.CNAME{
							Hdr:    dns.RR_Header{Name: "_acme-challenge.monitoring.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
							Target: "_acme-challenge.dns-validation.example.net.",
						},
					},
				}},
				{"CNAME _acme-challenge.dns-validation.example.net.", &dns.Msg{
					MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
					Answer: []dns.RR{},
				}},
			},
		},
		{
			// Failing to look up the challenge name is not a new failure mode:
			// followCNAMEs would have made the same query and failed too.
			name:      "challenge name lookup failure should be returned",
			domain:    "example.com",
			follow:    true,
			failQuery: "CNAME _acme-challenge.example.com.",
			failErr:   errors.New("simulated network failure"),
			mockDNS:   []interaction{},
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withMockDNSQueryFailing(t, tc.mockDNS, tc.failQuery, tc.failErr)
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
