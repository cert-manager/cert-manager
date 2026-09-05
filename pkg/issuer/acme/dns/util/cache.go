/*
Copyright 2026 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"k8s.io/apimachinery/pkg/util/wait"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// UseAuthoritative is a boolean flag that controls whether
// CheckTXTRecordPropagation resolves and queries the authoritative nameservers
// for the zone rather than querying the provided nameservers directly.
type UseAuthoritative bool

// Resolver performs DNS lookups needed for ACME DNS-01 challenge verification.
type Resolver interface {
	FindZoneByFQDN(ctx context.Context, fqdn string, nameservers []string) (string, error)
	LookupAuthoritativeNameservers(ctx context.Context, fqdn string, nameservers []string) ([]string, error)
	CheckTXTRecordPropagation(ctx context.Context, fqdn, value string, nameservers []string, useAuthoritative UseAuthoritative) (bool, error)
}

var _ Resolver = (*CachingResolver)(nil)

// CachingResolver is a per-nameserver DNS zone cache used during ACME DNS-01
// challenges. The zero value is safe to use; the internal map is lazily
// initialized on first write.
type CachingResolver struct {
	mu    sync.RWMutex
	cache map[cacheKey]cacheEntry
}

// NewCachingResolver returns a new CachingResolver.
func NewCachingResolver() *CachingResolver {
	return &CachingResolver{}
}

type (
	// cacheKey is the map key used to index entries in ZoneCache, composed
	// of the DNS record type, nameserver address, and fully-qualified domain name.
	cacheKey struct {
		Type       uint16
		Nameserver string
		FQDN       string
	}

	// cacheEntry holds a cached DNS response together with the absolute time
	// at which the entry expires, derived from the record TTL at insertion time.
	cacheEntry struct {
		Response *dns.Msg
		Expiry   time.Time
	}
)

// FindZoneByFQDN walks up the DNS label tree for fqdn, querying each nameserver
// in order for an SOA record to identify the zone apex. The cache is checked
// for each nameserver in the order given and the first cached result is returned
// immediately. On a cache miss, nameservers are queried in order until one
// succeeds and the result is cached per-nameserver for the SOA TTL duration.
// If a nameserver returns an error the search continues to the next and an error
// is returned only when all nameservers fail.
func (c *CachingResolver) FindZoneByFQDN(ctx context.Context, fqdn string, nameservers []string) (string, error) {
	// Get the current time once to avoid getting it at various points in the code
	now := time.Now()

	// Fast path, attempt to find the value in the cache
	for _, nameserver := range nameservers {
		// The cache key for this nameserver/fqdn combo
		key := cacheKey{
			Type:       dns.TypeSOA,
			Nameserver: nameserver,
			FQDN:       fqdn,
		}

		// Cache hit, return from cache
		if entry, exists := c.getCache(key, now); exists {
			logf.FromContext(ctx).V(logf.DebugLevel).Info("Returning cached DNS response", "type", "soa", "fqdn", fqdn, "nameserver", nameserver)
			for _, ans := range entry.Response.Answer {
				if soa, ok := ans.(*dns.SOA); ok {
					return soa.Hdr.Name, nil
				}
			}

			logf.FromContext(ctx).V(logf.WarnLevel).Info("Cached response has no SOA records, retrying DNS query", "fqdn", fqdn, "nameserver", nameserver)
		}
	}

	// Cache miss, try and obtain the value. Error messages inside this callback
	// deliberately reference the outer nameservers slice rather than the single
	// nameserver argument. tryAllNameservers only propagates the last error, so
	// using the full list preserves the context of what was attempted across all
	// nameservers rather than implying only one was tried.
	return tryAllNameservers(nameservers, func(nameserver string) (string, error) {
		// The cache key for this nameserver/fqdn combo
		key := cacheKey{
			Type:       dns.TypeSOA,
			Nameserver: nameserver,
			FQDN:       fqdn,
		}

		// Split the FQDN into its parts
		labelIndexes := dns.Split(fqdn)

		// We are climbing up the domain tree, looking for the SOA record on
		// one of them. For example, imagine that the DNS tree looks like this:
		//
		//  example.com.                                   ← SOA is here.
		//  └── foo.example.com.
		//      └── _acme-challenge.foo.example.com.       ← Starting point.
		//
		// We start at the bottom of the tree and climb up. The NXDOMAIN error
		// lets us know that we should climb higher:
		//
		//  _acme-challenge.foo.example.com. returns NXDOMAIN
		//                  foo.example.com. returns NXDOMAIN
		//                      example.com. returns NOERROR along with the SOA
		for _, index := range labelIndexes {
			domain := fqdn[index:]

			in, err := dnsQuery(ctx, domain, dns.TypeSOA, []string{nameserver}, true)
			if err != nil {
				return "", err
			}

			// NXDOMAIN tells us that we did not climb far enough up the DNS tree. We
			// thus continue climbing to find the SOA record.
			if in.Rcode == dns.RcodeNameError {
				continue
			}

			// Any non-successful response code, other than NXDOMAIN, is treated as an error
			// and interrupts the search.
			if in.Rcode != dns.RcodeSuccess {
				return "", fmt.Errorf("When querying the SOA record for the domain '%s' using nameservers %v, rcode was expected to be 'NOERROR' or 'NXDOMAIN', but got '%s'",
					domain, nameservers, dns.RcodeToString[in.Rcode])
			}

			// As per RFC 2181, CNAME records cannot not exist at the root of a zone,
			// which means we won't be finding any SOA record for this domain.
			if dnsMsgContainsCNAME(in) {
				continue
			}

			for _, ans := range in.Answer {
				if soa, ok := ans.(*dns.SOA); ok {
					logf.FromContext(ctx).V(logf.DebugLevel).Info("Caching DNS response", "type", "soa", "fqdn", fqdn, "ttl", soa.Hdr.Ttl, "nameserver", nameserver)
					c.putCache(key, cacheEntry{
						Response: in,
						Expiry:   now.Add(time.Duration(soa.Hdr.Ttl) * time.Second),
					})

					return soa.Hdr.Name, nil
				}
			}
		}

		return "", fmt.Errorf("Could not find the SOA record in the DNS tree for the domain '%s' using nameservers %v", fqdn, nameservers)
	})
}

// LookupAuthoritativeNameservers queries NS records for the zone that contains
// fqdn, trying each nameserver in order and returning the first successful
// result. Results are cached for the duration of the shortest NS record TTL.
func (c *CachingResolver) LookupAuthoritativeNameservers(ctx context.Context, fqdn string, nameservers []string) ([]string, error) {
	// Get the current time once to avoid getting it at various points in the code
	now := time.Now()

	// Fast path, attempt to find the value in the cache
	for _, nameserver := range nameservers {
		// The cache key for this nameserver/fqdn combo
		key := cacheKey{
			Type:       dns.TypeNS,
			Nameserver: nameserver,
			FQDN:       fqdn,
		}

		// Cache hit, return from cache
		if entry, exists := c.getCache(key, now); exists {
			var authoritativeNSs []string

			logf.FromContext(ctx).V(logf.DebugLevel).Info("Returning cached DNS response", "type", "ns", "fqdn", fqdn, "nameserver", nameserver)
			for _, rr := range entry.Response.Answer {
				if ns, ok := rr.(*dns.NS); ok {
					authoritativeNSs = append(authoritativeNSs, strings.ToLower(ns.Ns))
				}
			}

			if len(authoritativeNSs) != 0 {
				logf.FromContext(ctx).V(logf.DebugLevel).Info("Returning authoritative nameservers", "authoritativeNameservers", authoritativeNSs)
				return authoritativeNSs, nil
			}

			logf.FromContext(ctx).V(logf.WarnLevel).Info("Cached response has no NS records, retrying DNS query", "fqdn", fqdn, "nameserver", nameserver)
		}
	}

	// Cache miss, query DNS
	return tryAllNameservers(nameservers, func(nameserver string) ([]string, error) {
		var authoritativeNSs []string

		// The cache key for this nameserver/fqdn combo
		key := cacheKey{
			Type:       dns.TypeNS,
			Nameserver: nameserver,
			FQDN:       fqdn,
		}

		// Get the FQDN using the provided nameservers
		logf.FromContext(ctx).V(logf.DebugLevel).Info("Searching fqdn", "fqdn", fqdn, "seedNameservers", nameservers)
		zone, err := c.FindZoneByFQDN(ctx, fqdn, []string{nameserver})
		if err != nil {
			return nil, fmt.Errorf("Could not determine the zone for %q: %v", fqdn, err)
		}

		// Query for the NS record
		r, err := dnsQuery(ctx, zone, dns.TypeNS, []string{nameserver}, true)
		if err != nil {
			return nil, err
		}

		// Loop over NS records, adding them to the slice. Track the minimum
		// TTL across all records so the cache entry expires at the right time.
		ttl := time.Duration(0)
		for _, rr := range r.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				authoritativeNSs = append(authoritativeNSs, strings.ToLower(ns.Ns))
				if newTTL := time.Second * time.Duration(ns.Hdr.Ttl); newTTL < ttl || ttl == 0 {
					ttl = newTTL
				}
			}
		}

		// If we did not find any NS records, continue
		if len(authoritativeNSs) == 0 {
			return nil, fmt.Errorf("Could not determine authoritative nameservers for %q", fqdn)
		}

		logf.FromContext(ctx).V(logf.DebugLevel).Info("Caching DNS response", "type", "ns", "fqdn", fqdn, "ttl", ttl, "nameserver", nameserver)
		c.putCache(key, cacheEntry{
			Response: r,
			Expiry:   now.Add(ttl),
		})

		logf.FromContext(ctx).V(logf.DebugLevel).Info("Returning authoritative nameservers", "authoritativeNameservers", authoritativeNSs)
		return authoritativeNSs, nil
	})
}

// CheckTXTRecordPropagation follows any CNAME chain for fqdn, then verifies
// that value is present in the TXT records returned by the configured nameservers.
// When useAuthoritative is true, the authoritative nameservers for the zone are
// resolved via LookupAuthoritativeNameservers and queried instead.
func (c *CachingResolver) CheckTXTRecordPropagation(
	ctx context.Context,
	fqdn, value string,
	configuredNSs []string,
	useAuthoritative UseAuthoritative,
) (bool, error) {

	// Follow CNAME records to find the real FQDN
	var err error
	fqdn, err = followCNAMEs(ctx, fqdn, configuredNSs)
	if err != nil {
		return false, err
	}

	// If we are not using the authoritative servers just directly check the
	// configured nameservers
	if !useAuthoritative {
		return checkTXTRecord(ctx, fqdn, value, configuredNSs)
	}

	// Find the authoritative nameservers
	authoritativeNSs, err := c.LookupAuthoritativeNameservers(ctx, fqdn, configuredNSs)
	if err != nil {
		return false, err
	}

	// Convert the return nameservers to the correct format <ip>:<port>
	for i, ans := range authoritativeNSs {
		authoritativeNSs[i] = net.JoinHostPort(ans, "53")
	}

	// Check for the TXT record using the authoritative nameservers
	return checkTXTRecord(ctx, fqdn, value, authoritativeNSs)
}

func (c *CachingResolver) putCache(key cacheKey, value cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Lazy initialize map if it is nil
	if c.cache == nil {
		c.cache = make(map[cacheKey]cacheEntry)
	}

	// Set cache value
	c.cache[key] = value
}

func (c *CachingResolver) getCache(key cacheKey, now time.Time) (cacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[key]
	return entry, exists && now.Before(entry.Expiry)
}

// Start runs a background goroutine that evicts expired cache entries every
// minute. It blocks until ctx is cancelled, making it suitable for registration
// with a controller-runtime manager or direct use in a goroutine.
//
// The cache is perfectly safe to use without calling Start, with the
// understanding that it will never evict cache entries. This can be useful for
// short lived unit tests.
func (c *CachingResolver) Start(ctx context.Context) error {
	wait.UntilWithContext(ctx, c.clean, time.Minute)
	return nil
}

// clean removes all cache entries whose TTL has elapsed. It is called
// periodically by Start.
func (c *CachingResolver) clean(ctx context.Context) {
	now := time.Now()

	// Grab lock
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clean expired items
	for k, v := range c.cache {
		if now.After(v.Expiry) {
			delete(c.cache, k)
		}
	}
}

// tryAllNameservers calls fn for each nameserver in order and returns the first
// non-error result. If every nameserver produces an error, the error from the
// last attempt is returned.
func tryAllNameservers[T any](nameservers []string, fn func(nameserver string) (T, error)) (value T, err error) {
	if len(nameservers) == 0 {
		return value, fmt.Errorf("nameservers is required")
	}

	for _, nameserver := range nameservers {
		value, err = fn(nameserver)
		if err == nil {
			return value, nil
		}
	}

	return
}
