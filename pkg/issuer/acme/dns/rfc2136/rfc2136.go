/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"k8s.io/klog"
)

var defaultPort = "53"

var supportedAlgorithms = map[string]string{
	"HMACMD5":    dns.HmacMD5,
	"HMACSHA1":   dns.HmacSHA1,
	"HMACSHA256": dns.HmacSHA256,
	"HMACSHA512": dns.HmacSHA512,
}

// Returns a slice of all the supported algorithms
// It should contain all listed in https://tools.ietf.org/html/rfc4635#section-2
// but miekd/dns supports only supportedAlgorithms(keys)
func GetSupportedAlgorithms() []string {
	keys := reflect.ValueOf(supportedAlgorithms).MapKeys()
	strkeys := make([]string, len(keys))
	for i := 0; i < len(keys); i++ {
		strkeys[i] = keys[i].String()
	}
	sort.Strings(strkeys)
	return strkeys
}

// This function make a valid nameserver as per RFC2136
func ValidNameserver(nameserver string) (string, error) {

	if nameserver == "" {
		return "", fmt.Errorf("RFC2136 nameserver missing")
	}

	// SplitHostPort Behavior
	// namserver           host                port    err
	// 8.8.8.8             ""                  ""      missing port in address
	// 8.8.8.8:            "8.8.8.8"           ""      <nil>
	// 8.8.8.8.8:53        "8.8.8.8"           53      <nil>
	// nameserver.com      ""                  ""      missing port in address
	// nameserver.com:     "nameserver.com"    ""      <nil>
	// nameserver.com:53   "nameserver.com"    53      <nil>
	// :53                 ""                  53      <nil>
	host, port, err := net.SplitHostPort(strings.TrimSpace(nameserver))

	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			host = nameserver
		}
	}

	if port == "" {
		port = defaultPort
	}

	if host != "" {
		if ipaddr := net.ParseIP(host); ipaddr == nil {
			return "", fmt.Errorf("RFC2136 nameserver must be a valid IP Address, not %v", host)
		}
	} else {
		return "", fmt.Errorf("RFC2136 nameserver has no IP Address defined, %v", nameserver)
	}

	nameserver = host + ":" + port

	return nameserver, nil
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
	klog.V(5).Infof("Creating RFC2136 Provider")

	d := &DNSProvider{}

	if validNameserver, err := ValidNameserver(nameserver); err != nil {
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
			return nil, fmt.Errorf("The algorithm '%v' is not supported", tsigAlgorithm)

		}
	}
	d.tsigAlgorithm = tsigAlgorithm

	klog.V(5).Infof("DNSProvider nameserver:       %s\n", d.nameserver)
	klog.V(5).Infof("            tsigAlgorithm:    %s\n", d.tsigAlgorithm)
	klog.V(5).Infof("            tsigKeyName:      %s\n", d.tsigKeyName)
	keyLen := len(d.tsigSecret)
	mask := make([]rune, keyLen/2)
	for i := range mask {
		mask[i] = '*'
	}
	masked := d.tsigSecret[0:keyLen/4] + string(mask) + d.tsigSecret[keyLen/4*3:keyLen]
	klog.V(5).Infof("            tsigSecret:       %s\n", masked)

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

func (r *DNSProvider) changeRecord(action, fqdn, zone, value string, ttl int) error {
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
