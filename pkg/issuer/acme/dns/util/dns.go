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

	"github.com/miekg/dns"
)

// DNS01LookupFQDN returns a DNS name which will be updated to solve the dns-01
// challenge
// TODO: move this into the pkg/acme package
func DNS01LookupFQDN(ctx context.Context, domain string, followCNAME bool, nameservers ...string) (string, error) {
	fqdn := fmt.Sprintf("_acme-challenge.%s.", domain)

	// Check if the domain has CNAME then return that
	if followCNAME {
		// Before following CNAMEs, check that the CNAME record is explicitly
		// set on the _acme-challenge subdomain and not inherited from a
		// wildcard record on the parent domain. Wildcard CNAMEs (e.g.,
		// *.example.com) should not be followed because they would direct
		// the challenge to a zone we likely don't control.
		// See: https://github.com/cert-manager/cert-manager/issues/5751
		isWildcard, err := isWildcardCNAME(ctx, fqdn, domain, nameservers)
		if err != nil {
			return "", err
		}
		if !isWildcard {
			fqdn, err = followCNAMEs(ctx, fqdn, nameservers)
			if err != nil {
				return "", err
			}
		}
	}

	return fqdn, nil
}

// isWildcardCNAME checks whether the CNAME record returned for fqdn is
// synthesized from a wildcard record on the parent domain rather than being an
// explicit record. It does this by querying both the fqdn and the wildcard
// entry of the parent domain; if both return CNAME records pointing to the same
// target, the record is considered to be from a wildcard and should not be
// followed.
func isWildcardCNAME(ctx context.Context, fqdn, domain string, nameservers []string) (bool, error) {
	// Query the CNAME for the exact _acme-challenge FQDN.
	r, err := dnsQuery(ctx, fqdn, dns.TypeCNAME, nameservers, true)
	if err != nil {
		return false, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return false, nil
	}

	// Extract the CNAME target for the challenge subdomain.
	var challengeTarget string
	for _, rr := range r.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			challengeTarget = cn.Target
			break
		}
	}
	if challengeTarget == "" {
		// No CNAME record found, nothing to follow.
		return false, nil
	}

	// Query the wildcard CNAME for the parent domain.
	wildcardFQDN := fmt.Sprintf("*.%s.", domain)
	rWild, err := dnsQuery(ctx, wildcardFQDN, dns.TypeCNAME, nameservers, true)
	if err != nil {
		return false, err
	}
	if rWild.Rcode != dns.RcodeSuccess {
		// No wildcard record exists, so the CNAME is explicit.
		return false, nil
	}

	// Check if any wildcard CNAME target matches the challenge CNAME target.
	for _, rr := range rWild.Answer {
		if cn, ok := rr.(*dns.CNAME); ok && cn.Target == challengeTarget {
			return true, nil
		}
	}

	return false, nil
}

// FindBestMatch returns the longest match for a given domain within a list of domains
func FindBestMatch(query string, domains ...string) (string, error) {
	var maxSoFar int
	var longest string

	for _, domain := range domains {
		if query == domain {
			// Found exact match
			return domain, nil
		}

		maxHere := dns.CompareDomainName(query, domain)
		if maxHere > maxSoFar && dns.IsSubDomain(domain, query) {
			maxSoFar = maxHere
			longest = domain
		}
	}

	if len(longest) == 0 {
		return "", fmt.Errorf("query: %v has no matches", query)
	}
	return longest, nil
}
