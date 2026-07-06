// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package util

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// maxDNSResponseSize is the max size of a received DNS-over-HTTPS response
// body. DNS over TCP responses are limited to 65535 bytes by RFC 1035; this
// is set to a generous 128KB to allow for overhead while still preventing a
// malicious DoH server from sending an arbitrarily large response.
const maxDNSResponseSize = 128 * 1024

type preCheckDNSFunc func(ctx context.Context, fqdn, value string, nameservers []string,
	useAuthoritative bool) (bool, error)
type dnsQueryFunc func(ctx context.Context, fqdn string, rtype uint16, nameservers []string, recursive bool) (in *dns.Msg, err error)

var (
	// PreCheckDNS checks DNS propagation before notifying ACME that
	// the DNS challenge is ready.
	//
	// Deprecated: The CachingResolver struct has replaced this functionality
	PreCheckDNS preCheckDNSFunc = checkDNSPropagation

	// dnsQuery is used to be able to mock DNSQuery
	dnsQuery dnsQueryFunc = DNSQuery

	// We have moved functionality to the CachingResolver, in order to not break
	// anything importing this package we have the original functions use this
	// instance.
	//
	// Every call to LegacyCachedResolver will return the same Resolver, it is
	// safe to call multiple times.
	//
	// The legacy cache resolver starts a goroutine to clean the cache that
	// cannot be stopped.
	//
	// Deprecated: The CachingResolver struct has replaced this functionality
	LegacyCachedResolver = sync.OnceValue(func() Resolver {
		cache := &CachingResolver{}
		//nolint:errcheck // Error is returned to satisfy the runnable interface, in reality it should never error
		go cache.Start(context.Background())
		return cache
	})
)

const defaultResolvConf = "/etc/resolv.conf"

var defaultNameservers = []string{
	"8.8.8.8:53",
	"8.8.4.4:53",
}

var RecursiveNameservers = getNameservers(defaultResolvConf, defaultNameservers)

// DNSTimeout is used to override the default DNS timeout of 10 seconds.
var DNSTimeout = 10 * time.Second

// getNameservers attempts to get systems nameservers before falling back to the defaults
func getNameservers(path string, defaults []string) []string {
	config, err := dns.ClientConfigFromFile(path)
	if err != nil || len(config.Servers) == 0 {
		return defaults
	}

	systemNameservers := []string{}
	for _, server := range config.Servers {
		// ensure all servers have a port number
		if _, _, err := net.SplitHostPort(server); err != nil {
			systemNameservers = append(systemNameservers, net.JoinHostPort(server, "53"))
		} else {
			systemNameservers = append(systemNameservers, server)
		}
	}
	return systemNameservers
}

// Follows the CNAME records and returns the last non-CNAME fully qualified domain name
// that it finds. Returns an error when a loop is found in the CNAME chain. The
// argument fqdnChain is used by the function itself to keep track of which fqdns it
// already encountered and detect loops.
func followCNAMEs(ctx context.Context, fqdn string, nameservers []string, fqdnChain ...string) (string, error) {
	r, err := dnsQuery(ctx, fqdn, dns.TypeCNAME, nameservers, true)
	if err != nil {
		return "", err
	}
	if r.Rcode != dns.RcodeSuccess {
		return fqdn, err
	}
	for _, rr := range r.Answer {
		cn, ok := rr.(*dns.CNAME)
		if !ok || cn.Hdr.Name != fqdn {
			continue
		}
		logf.FromContext(ctx).V(logf.DebugLevel).Info("Updating FQDN", "fqdn", fqdn, "cname", cn.Target)
		// Check if we were here before to prevent loops in the chain of CNAME records.
		for _, fqdnInChain := range fqdnChain {
			if cn.Target != fqdnInChain {
				continue
			}
			return "", fmt.Errorf("Found recursive CNAME record to %q when looking up %q", cn.Target, fqdn)
		}
		return followCNAMEs(ctx, cn.Target, nameservers, append(fqdnChain, fqdn)...)
	}
	return fqdn, nil
}

// checkDNSPropagation checks if the expected TXT record has been propagated to all authoritative nameservers.
func checkDNSPropagation(ctx context.Context, fqdn, value string, nameservers []string,
	useAuthoritative bool) (bool, error) {

	return LegacyCachedResolver().
		CheckTXTRecordPropagation(ctx, fqdn, value, nameservers, UseAuthoritative(useAuthoritative))
}

// checkAuthoritativeNss queries each of the given nameservers for the expected TXT record.
func checkAuthoritativeNss(ctx context.Context, fqdn, value string, nameservers []string) (bool, error) {
	for _, ns := range nameservers {
		r, err := dnsQuery(ctx, fqdn, dns.TypeTXT, []string{ns}, true)
		if err != nil {
			return false, err
		}

		// NXDomain response is not really an error, just waiting for propagation to happen
		if !(r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError) {
			return false, fmt.Errorf("NS %s returned %s for %s", ns, dns.RcodeToString[r.Rcode], fqdn)
		}

		logf.FromContext(ctx).V(logf.DebugLevel).Info("Looking up TXT records", "fqdn", fqdn)
		var found bool
		for _, rr := range r.Answer {
			if txt, ok := rr.(*dns.TXT); ok {
				if strings.Join(txt.Txt, "") == value {
					found = true
					break
				}
			}
		}

		if !found {
			return false, nil
		}
	}
	logf.FromContext(ctx).V(logf.DebugLevel).Info("Selfchecking using the DNS Lookup method was successful")
	return true, nil
}

// DNSQuery will query a nameserver, iterating through the supplied servers as it retries
// The nameserver should include a port, to facilitate testing where we talk to a mock dns server.
func DNSQuery(ctx context.Context, fqdn string, rtype uint16, nameservers []string, recursive bool) (in *dns.Msg, err error) {
	switch rtype {
	case dns.TypeCAA, dns.TypeCNAME, dns.TypeNS, dns.TypeSOA, dns.TypeTXT:
	default:
		// We explicitly specified here what types are supported, so we can more confidently create tests for this function.
		return nil, fmt.Errorf("unsupported DNS record type %d", rtype)
	}

	if len(nameservers) == 0 {
		return nil, fmt.Errorf("nameservers is required")
	}

	m := new(dns.Msg)
	m.SetQuestion(fqdn, rtype)
	m.SetEdns0(4096, false)

	if !recursive {
		m.RecursionDesired = false
	}

	udp := &dns.Client{Net: "udp", Timeout: DNSTimeout}
	tcp := &dns.Client{Net: "tcp", Timeout: DNSTimeout}
	httpClient := *http.DefaultClient
	httpClient.Timeout = DNSTimeout
	http := httpDNSClient{
		HTTPClient: &httpClient,
	}

	// Will retry the request based on the number of servers (n+1)
	for _, ns := range nameservers {
		// If the TCP request succeeds, the err will reset to nil
		if strings.HasPrefix(ns, "https://") {
			in, _, err = http.Exchange(ctx, m, ns)

		} else {
			in, _, err = udp.ExchangeContext(ctx, m, ns)

			// Try TCP if UDP fails
			if (in != nil && in.Truncated) ||
				(err != nil && strings.HasPrefix(err.Error(), "read udp") && strings.HasSuffix(err.Error(), "i/o timeout")) {
				logf.FromContext(ctx).V(logf.DebugLevel).Info("UDP dns lookup failed, retrying with TCP", "err", err)
				// If the TCP request succeeds, the err will reset to nil
				in, _, err = tcp.ExchangeContext(ctx, m, ns)
			}
		}

		if err == nil {
			break
		}
	}
	return in, err
}

type httpDNSClient struct {
	HTTPClient *http.Client
}

const dohMimeType = "application/dns-message"

func (c *httpDNSClient) Exchange(ctx context.Context, m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error) {
	p, err := m.Pack()
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a, bytes.NewReader(p))
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Content-Type", dohMimeType)
	req.Header.Set("Accept", dohMimeType)

	hc := http.DefaultClient
	if c.HTTPClient != nil {
		hc = c.HTTPClient
	}

	req = req.WithContext(ctx)

	t := time.Now()

	resp, err := hc.Do(req) // #nosec G704 -- TODO(erikgb): This is probably not a false positive. Investigate!
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("dns: server returned HTTP %d error: %q", resp.StatusCode, resp.Status)
	}

	if ct := resp.Header.Get("Content-Type"); ct != dohMimeType {
		return nil, 0, fmt.Errorf("dns: unexpected Content-Type %q; expected %q", ct, dohMimeType)
	}

	p, err = io.ReadAll(io.LimitReader(resp.Body, maxDNSResponseSize))
	if err != nil {
		return nil, 0, err
	}

	rtt = time.Since(t)

	r = new(dns.Msg)
	if err := r.Unpack(p); err != nil {
		return r, 0, err
	}

	return r, rtt, nil
}

// FindZoneByFqdn determines the zone apex for the given fqdn by recursing up the
// domain labels until the nameserver returns a SOA record in the answer section.
//
// Deprecated: The CachingResolver struct has replaced this functionality
func FindZoneByFqdn(ctx context.Context, fqdn string, nameservers []string) (string, error) {
	return LegacyCachedResolver().FindZoneByFQDN(ctx, fqdn, nameservers)
}

// dnsMsgContainsCNAME checks for a CNAME answer in msg
func dnsMsgContainsCNAME(msg *dns.Msg) bool {
	for _, ans := range msg.Answer {
		if _, ok := ans.(*dns.CNAME); ok {
			return true
		}
	}
	return false
}

// ToFqdn converts the name into a fqdn appending a trailing dot.
func ToFqdn(name string) string {
	if name == "" || strings.HasSuffix(name, ".") {
		return name
	}

	return name + "."
}

// UnFqdn converts the fqdn into a name removing the trailing dot.
func UnFqdn(name string) string {
	return strings.TrimSuffix(name, ".")
}

// WaitFor polls the given function 'f', once every 'interval', up to 'timeout'.
func WaitFor(timeout, interval time.Duration, f func() (bool, error)) error {
	var lastErr string
	timeup := time.After(timeout)
	for {
		select {
		case <-timeup:
			return fmt.Errorf("Time limit exceeded. Last error: %s", lastErr)
		default:
		}

		stop, err := f()
		if stop {
			return nil
		}
		if err != nil {
			lastErr = err.Error()
		}

		time.Sleep(interval)
	}
}
