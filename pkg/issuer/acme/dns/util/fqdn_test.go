/*
Copyright 2025 The cert-manager Authors.

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
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// This file contains code adapted from a contribution sent by Oleh Konko as part of GHSA-gx3x-vq4p-mhhv

func Test_FindZoneByFqdn_NoPanic(t *testing.T) {
	zone := "example.com."
	fqdn := fmt.Sprintf("findzonebyfqdn.%s", zone)

	// start the dummy DNS server which we'll query
	ns, stop := startDNS(t, zone)
	defer stop()

	// First call to FindZoneByFqdn to populate the cache
	_, err := FindZoneByFqdn(t.Context(), fqdn, []string{ns})
	if err != nil {
		t.Fatalf("first call too FindZoneByFqdn failed: %v", err)
	}

	// We want to test that the second call does not panic; catch a panic here for prettier log output

	defer func() {
		r := recover()
		if r != nil {
			t.Fatalf("got a panic but none expected: %v", r)
		}
	}()

	// Second call to FindZoneByFqdn should find the SOA record in the cached response without panic

	_, err = FindZoneByFqdn(t.Context(), fqdn, []string{ns})
	if err != nil {
		t.Fatalf("second call too FindZoneByFqdn failed: %v", err)
	}
}

// startDNS starts a local DNS server that responds with a fixed SOA record for any query
func startDNS(t *testing.T, zone string) (addr string, stop func()) {
	t.Helper()

	lc := &net.ListenConfig{}

	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}

	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		qname := zone
		if len(r.Question) > 0 {
			qname = r.Question[0].Name
		}

		// this is specially crafted: the SOA record exists but is not at Answer[0]
		m.Answer = []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 600},
				Ns:  "ns1.example.com.",
			},
			&dns.SOA{
				Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 600},
				Ns:      "ns1.example.com.",
				Mbox:    "hostmaster.example.com.",
				Serial:  1,
				Refresh: 3600,
				Retry:   600,
				Expire:  86400,
				Minttl:  60,
			},
		}

		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() {
		_ = srv.ActivateAndServe()
	}()

	return pc.LocalAddr().String(), func() {
		_ = srv.ShutdownContext(t.Context())
		_ = pc.Close()
	}
}
