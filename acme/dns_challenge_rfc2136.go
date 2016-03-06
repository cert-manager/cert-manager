package acme

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSProviderRFC2136 is an implementation of the ChallengeProvider interface that
// uses dynamic DNS updates (RFC 2136) to create TXT records on a nameserver.
type DNSProviderRFC2136 struct {
	nameserver    string
	tsigAlgorithm string
	tsigKey       string
	tsigSecret    string
}

// NewDNSProviderRFC2136 returns a new DNSProviderRFC2136 instance.
// To disable TSIG authentication 'tsigAlgorithm, 'tsigKey' and 'tsigSecret' must be set to the empty string.
// 'nameserver' must be a network address in the the form "host" or "host:port".
func NewDNSProviderRFC2136(nameserver, tsigAlgorithm, tsigKey, tsigSecret string) (*DNSProviderRFC2136, error) {
	// Append the default DNS port if none is specified.
	if _, _, err := net.SplitHostPort(nameserver); err != nil {
		if strings.Contains(err.Error(), "missing port") {
			nameserver = net.JoinHostPort(nameserver, "53")
		} else {
			return nil, err
		}
	}
	d := &DNSProviderRFC2136{
		nameserver: nameserver,
	}
	if tsigAlgorithm == "" {
		tsigAlgorithm = dns.HmacMD5
	}
	d.tsigAlgorithm = tsigAlgorithm
	if len(tsigKey) > 0 && len(tsigSecret) > 0 {
		d.tsigKey = tsigKey
		d.tsigSecret = tsigSecret
	}

	return d, nil
}

// Present creates a TXT record using the specified parameters
func (r *DNSProviderRFC2136) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl := DNS01Record(domain, keyAuth)
	return r.changeRecord("INSERT", fqdn, value, ttl)
}

// CleanUp removes the TXT record matching the specified parameters
func (r *DNSProviderRFC2136) CleanUp(domain, token, keyAuth string) error {
	fqdn, value, ttl := DNS01Record(domain, keyAuth)
	return r.changeRecord("REMOVE", fqdn, value, ttl)
}

func (r *DNSProviderRFC2136) changeRecord(action, fqdn, value string, ttl int) error {
	// Find the zone for the given fqdn
	zone, err := findZoneByFqdn(fqdn, r.nameserver)
	if err != nil {
		return err
	}

	// Create RR
	rr := new(dns.TXT)
	rr.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(ttl)}
	rr.Txt = []string{value}
	rrs := []dns.RR{rr}

	// Create dynamic update packet
	m := new(dns.Msg)
	m.SetUpdate(zone)
	switch action {
	case "INSERT":
		// Always remove old challenge left over from who knows what.
		m.RemoveRRset(rrs)
		m.Insert(rrs)
	case "REMOVE":
		m.Remove(rrs)
	default:
		return fmt.Errorf("Unexpected action: %s", action)
	}

	// Setup client
	c := new(dns.Client)
	c.SingleInflight = true
	// TSIG authentication / msg signing
	if len(r.tsigKey) > 0 && len(r.tsigSecret) > 0 {
		m.SetTsig(dns.Fqdn(r.tsigKey), r.tsigAlgorithm, 300, time.Now().Unix())
		c.TsigSecret = map[string]string{dns.Fqdn(r.tsigKey): r.tsigSecret}
	}

	// Send the query
	reply, _, err := c.Exchange(m, r.nameserver)
	if err != nil {
		return fmt.Errorf("DNS update failed: %v", err)
	}
	if reply != nil && reply.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS update failed. Server replied: %s", dns.RcodeToString[reply.Rcode])
	}

	return nil
}
