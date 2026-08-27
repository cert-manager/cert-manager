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
	"strings"

	"github.com/miekg/dns"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// DNS01LookupFQDN returns a DNS name which will be updated to solve the dns-01
// challenge
// TODO: move this into the pkg/acme package
func DNS01LookupFQDN(ctx context.Context, domain string, followCNAME bool, nameservers ...string) (string, error) {
	fqdn := fmt.Sprintf("_acme-challenge.%s.", domain)

	if !followCNAME {
		return fqdn, nil
	}

	// Resolve the first hop of the CNAME chain here rather than leaving it to
	// followCNAMEs, so that the answer can be used both for the wildcard check
	// below and for the rest of the chain. There is no cache on this path, so
	// querying it twice would mean an extra live query on every lookup.
	target, err := lookupCNAMETarget(ctx, fqdn, nameservers)
	if err != nil {
		return "", err
	}
	if target == "" {
		// No CNAME record on the challenge name, so there is nothing to follow.
		logf.FromContext(ctx).V(logf.DebugLevel).Info("No CNAME found", "fqdn", fqdn)
		return fqdn, nil
	}

	// A CNAME answer for the challenge name is not necessarily a record of its
	// own: if a wildcard CNAME covers the name, the resolver synthesizes the
	// answer from it. Such a target is almost always in a zone we cannot write
	// to, so following it would put the challenge record where the ACME server
	// will never look for it.
	// See: https://github.com/cert-manager/cert-manager/issues/5751
	if isWildcardCNAME(ctx, domain, target, nameservers) {
		logf.FromContext(ctx).V(logf.InfoLevel).Info("Not following CNAME because it appears to be synthesized by a wildcard record", "fqdn", fqdn, "cname", target)
		return fqdn, nil
	}

	logf.FromContext(ctx).V(logf.DebugLevel).Info("Updating FQDN", "fqdn", fqdn, "cname", target)

	// Continue from the hop that has already been resolved. fqdn is seeded into
	// the chain so that a CNAME pointing back at it is still reported as a loop.
	return followCNAMEs(ctx, target, nameservers, fqdn)
}

// isWildcardCNAME reports whether challengeTarget, the CNAME target resolved for
// the _acme-challenge name of domain, looks like it was synthesized from a
// wildcard CNAME record rather than read from a record of its own.
//
// It probes the literal wildcard name and compares the targets. Querying "*." is
// legitimate: RFC 4592 section 2.2.1 treats an asterisk in a query name as an
// ordinary label, so the probe returns the wildcard's own records when one
// exists at that level. A wildcard higher in the tree is found too. If
// *.example.com covers _acme-challenge.app.example.com because app.example.com
// has no records of its own, then the probe name *.app.example.com is
// synthesized by that same wildcard and gives the same target.
//
// A recursive answer does not say which of its records were synthesized, so two
// corner cases are accepted:
//
//   - An explicit _acme-challenge CNAME whose target happens to equal the
//     wildcard's target is treated as synthesized and is not followed.
//   - A wildcard-synthesized CNAME further down the chain is still followed,
//     because only the first hop is checked.
//
// Errors are not returned. This probe is an extra query that cert-manager did
// not previously make, so a transient failure of it must not fail a lookup that
// used to succeed; the error is logged and the CNAME is followed as before.
func isWildcardCNAME(ctx context.Context, domain, challengeTarget string, nameservers []string) bool {
	wildcardFQDN := fmt.Sprintf("*.%s.", domain)

	wildcardTarget, err := lookupCNAMETarget(ctx, wildcardFQDN, nameservers)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to check for a wildcard CNAME record, following the CNAME record as before", "fqdn", wildcardFQDN)
		return false
	}
	if wildcardTarget == "" {
		// No wildcard record exists, so the CNAME is a record of its own.
		return false
	}

	// DNS names compare case-insensitively, and the two answers may not
	// preserve the same case.
	return strings.EqualFold(wildcardTarget, challengeTarget)
}

// lookupCNAMETarget returns the target of the CNAME record owned by fqdn, or an
// empty string if there is none.
//
// A recursive resolver may return the whole chased chain in the answer section,
// so records owned by another name are skipped rather than assuming the first
// CNAME in the answer is the one that was asked for.
func lookupCNAMETarget(ctx context.Context, fqdn string, nameservers []string) (string, error) {
	r, err := dnsQuery(ctx, fqdn, dns.TypeCNAME, nameservers, true)
	if err != nil {
		return "", err
	}
	// NXDOMAIN means the name does not exist, so there is no CNAME to use. Any
	// other non-NOERROR rcode (SERVFAIL, REFUSED, ...) means it is unknown
	// whether a CNAME exists, which must not be silently treated as "no CNAME":
	// the challenge record would then be created under the wrong name.
	// See: https://github.com/cert-manager/cert-manager/issues/8095
	switch r.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return "", nil
	default:
		return "", errUnexpectedRcode(fqdn, nameservers, r.Rcode)
	}

	for _, rr := range r.Answer {
		if cn, ok := rr.(*dns.CNAME); ok && strings.EqualFold(cn.Hdr.Name, fqdn) {
			return cn.Target, nil
		}
	}

	return "", nil
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
