/*
Copyright 2020 The cert-manager Authors.

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

// Package rfc2136 implements a DNS provider for solving the DNS-01 challenge
// using the rfc2136 dynamic update.
// This code was adapted from lego:
// 	  https://github.com/xenolf/lego

package rfc2136

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/cert-manager/cert-manager/internal/apis/certmanager/validation/util"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// This list must be kept in sync with internal/apis/certmanager/validation/issuer.go
var supportedAlgorithms = map[string]string{
	"HMACMD5":    dns.HmacMD5,
	"HMACSHA1":   dns.HmacSHA1,
	"HMACSHA256": dns.HmacSHA256,
	"HMACSHA512": dns.HmacSHA512,
}

// DNSProvider is an implementation of the acme.ChallengeProvider interface that
// uses dynamic DNS updates (RFC 2136) to create TXT records on a nameserver.
type DNSProvider struct {
	nameserver    string
	tsigAlgorithm string
	tsigKeyName   string
	tsigSecret    string
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for rfc2136 dynamic update. To disable TSIG
// authentication, leave the TSIG parameters as empty strings.
// nameserver must be a network address in the form "IP" or "IP:port".
func NewDNSProviderCredentials(nameserver, tsigAlgorithm, tsigKeyName, tsigSecret string) (*DNSProvider, error) {
	logf.Log.V(logf.DebugLevel).Info("Creating RFC2136 Provider")

	d := &DNSProvider{}

	if validNameserver, err := util.ValidNameserver(nameserver); err != nil {
		return nil, err
	} else {
		d.nameserver = validNameserver
	}

	if len(tsigKeyName) > 0 && len(tsigSecret) > 0 {
		d.tsigKeyName = tsigKeyName
		d.tsigSecret = tsigSecret
	}

	if tsigAlgorithm == "" {
		tsigAlgorithm = dns.HmacMD5
	} else {
		if value, ok := supportedAlgorithms[strings.ToUpper(tsigAlgorithm)]; ok {
			tsigAlgorithm = value
		} else {
			return nil, fmt.Errorf("algorithm '%v' is not supported", tsigAlgorithm)

		}
	}
	d.tsigAlgorithm = tsigAlgorithm

	logf.V(logf.DebugLevel).Infof("DNSProvider nameserver:       %s\n", d.nameserver)
	logf.V(logf.DebugLevel).Infof("            tsigAlgorithm:    %s\n", d.tsigAlgorithm)
	logf.V(logf.DebugLevel).Infof("            tsigKeyName:      %s\n", d.tsigKeyName)
	keyLen := len(d.tsigSecret)
	mask := make([]rune, keyLen/2)
	for i := range mask {
		mask[i] = '*'
	}
	masked := d.tsigSecret[0:keyLen/4] + string(mask) + d.tsigSecret[keyLen/4*3:keyLen]
	logf.V(logf.DebugLevel).Infof("            tsigSecret:       %s\n", masked)

	return d, nil
}

// Present creates a TXT record using the specified parameters
func (r *DNSProvider) Present(_, fqdn, zone, value string) error {
	return r.changeRecord("INSERT", fqdn, zone, value, 60)
}

// CleanUp removes the TXT record matching the specified parameters
func (r *DNSProvider) CleanUp(_, fqdn, zone, value string) error {
	return r.changeRecord("REMOVE", fqdn, zone, value, 60)
}

func (r *DNSProvider) changeRecord(action, fqdn, zone, value string, ttl uint32) error {
	// Create RR
	rr := new(dns.TXT)
	rr.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}
	rr.Txt = []string{value}
	rrs := []dns.RR{rr}

	// Create dynamic update packet
	m := new(dns.Msg)
	m.SetUpdate(zone)
	switch action {
	case "INSERT":
		m.Insert(rrs)
	case "REMOVE":
		m.Remove(rrs)
	default:
		return fmt.Errorf("unexpected action: %s", action)
	}

	// Setup client
	c := new(dns.Client)
	c.TsigProvider = tsigHMACProvider(r.tsigSecret)
	// TSIG authentication / msg signing
	if len(r.tsigKeyName) > 0 && len(r.tsigSecret) > 0 {
		m.SetTsig(dns.Fqdn(r.tsigKeyName), r.tsigAlgorithm, 300, time.Now().Unix())
		c.TsigSecret = map[string]string{dns.Fqdn(r.tsigKeyName): r.tsigSecret}
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

// Nameserver returns the nameserver configured for this provider when it was created
func (r *DNSProvider) Nameserver() string {
	return r.nameserver
}

// TSIGAlgorithm returns the TSIG algorithm configured for this provider when it was created
func (r *DNSProvider) TSIGAlgorithm() string {
	return r.tsigAlgorithm
}
