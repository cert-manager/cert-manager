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
	originalFQDN := fmt.Sprintf("_acme-challenge.%s.", domain)

	if !followCNAME {
		return originalFQDN, nil
	}

	// Get zone for original domain to compare against later.
	// We use the domain (not originalFQDN) since _acme-challenge subdomain may not exist yet.
	originalZone, err := FindZoneByFqdn(ctx, fmt.Sprintf("%s.", domain), nameservers)
	if err != nil {
		// Can't find original zone, don't follow CNAMEs
		return originalFQDN, nil
	}

	// Try to follow CNAMEs
	resolvedFQDN, err := followCNAMEs(ctx, originalFQDN, nameservers)
	if err != nil {
		return "", err
	}

	// No CNAME found
	if resolvedFQDN == originalFQDN {
		return originalFQDN, nil
	}

	// Validate target zone is related to original.
	// This prevents wildcard CNAMEs (e.g., *.example.com → external.azure.com)
	// from redirecting ACME challenges to unrelated external zones.
	resolvedZone, err := FindZoneByFqdn(ctx, resolvedFQDN, nameservers)
	if err != nil {
		// Can't find zone for target - likely wildcard to external domain
		return originalFQDN, nil
	}

	if !isRelatedZone(originalZone, resolvedZone) {
		// Zones are unrelated - likely wildcard CNAME, fall back to original
		return originalFQDN, nil
	}

	return resolvedFQDN, nil
}

// isRelatedZone checks if two zones share common ancestry.
// Returns true if zones are same, parent/child, or share common parent.
// This is used to detect wildcard CNAME matches that point to unrelated zones.
func isRelatedZone(zone1, zone2 string) bool {
	if zone1 == zone2 {
		return true
	}

	// Check parent/child relationship
	if dns.IsSubDomain(zone1, zone2) || dns.IsSubDomain(zone2, zone1) {
		return true
	}

	// Check common ancestry (at least 2 matching suffix labels).
	// This allows sibling zones like foo.example.com and bar.example.com
	// but rejects completely unrelated zones like example.com and azure.com.
	labels1 := dns.SplitDomainName(zone1)
	labels2 := dns.SplitDomainName(zone2)

	if len(labels1) < 2 || len(labels2) < 2 {
		return false
	}

	matchingLabels := 0
	for i := 1; i <= min(len(labels1), len(labels2)); i++ {
		if labels1[len(labels1)-i] == labels2[len(labels2)-i] {
			matchingLabels++
		} else {
			break
		}
	}

	return matchingLabels >= 2
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
