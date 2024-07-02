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

package server

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/miekg/dns"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

type rfc2136Handler struct {
	t   *testing.T
	log logr.Logger

	txtRecords map[string][]string
	zones      []string
	tsigZone   string
	lock       sync.Mutex
}

// serveDNS implements github.com/miekg/dns.Handler
func (b *rfc2136Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	b.lock.Lock()
	defer b.lock.Unlock()
	log := b.log.WithName("serveDNS")

	m := new(dns.Msg)
	m.SetReply(req)
	defer func() {
		if err := w.WriteMsg(m); err != nil {
			b.t.Errorf("failed to write response: %v", err)
		}
	}()

	var zone string
	if len(req.Question) > 0 {
		question := req.Question[0].Name
		log = log.WithValues("question", question, "opcode", dns.OpcodeToString[req.Opcode])
		zone = b.zoneForFQDN(question)
		if zone == "" {
			log.V(logf.WarnLevel).Info("failed to lookup zone for fqdn")
			m.Rcode = dns.RcodeServerFailure
			return
		}
		log = log.WithValues("zone", zone)
	}

	if t := req.IsTsig(); t != nil {
		log.V(logf.DebugLevel).Info("TSIG requested on DNS request")
		if w.TsigStatus() == nil {
			log.V(logf.DebugLevel).Info("setting TSIG values on response")
			// Validated
			m.SetTsig(b.tsigZone, dns.HmacMD5, 300, time.Now().Unix())
		}
	}

	// updates are currently accepted for *all* zones
	if req.Opcode == dns.OpcodeUpdate {
		for _, rr := range req.Ns {
			txt := rr.(*dns.TXT)
			log := log.WithValues("value", txt.Hdr.Name, "class", dns.ClassToString[rr.Header().Class], "txt", txt.Txt)
			if rr.Header().Class == dns.ClassNONE {
				log.V(logf.DebugLevel).Info("deleting txt record value due to NONE class")
				// TODO: can we only delete the named record here somehow?
				delete(b.txtRecords, txt.Hdr.Name)
				continue
			}
			log.V(logf.DebugLevel).Info("setting TXT record value")
			b.txtRecords[txt.Hdr.Name] = txt.Txt
		}
	}

	switch req.Question[0].Qtype {
	case dns.TypeSOA:
		// Return SOA to appease findZoneByFqdn()
		soaRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN SOA ns1.%s admin.%s 2016022801 28800 7200 2419200 1200", zone, defaultTTL, zone, zone))
		m.Answer = []dns.RR{soaRR}
	case dns.TypeTXT:
		for _, rr := range b.txtRecords[req.Question[0].Name] {
			txtRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", req.Question[0].Name, defaultTTL, rr))
			m.Answer = append(m.Answer, txtRR)
		}
	}

	for _, rr := range m.Answer {
		log.V(logf.DebugLevel).Info("responding", "response", rr.String())
	}
}

func (b *rfc2136Handler) zoneForFQDN(s string) string {
	for _, z := range b.zones {
		if dns.IsSubDomain(z, s) {
			return z
		}
	}
	return ""
}
