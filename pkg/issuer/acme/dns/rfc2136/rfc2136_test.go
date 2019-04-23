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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"k8s.io/klog"
)

var (
	rfc2136TestDomain      = "123456789.www.example.com"
	rfc2136TestKeyAuth     = "123d=="
	rfc2136TestValue       = "Now36o-3BmlB623-0c1qCIUmgWVVmDJb88KGl24pqpo"
	rfc2136TestFqdn        = "_acme-challenge.123456789.www.example.com."
	rfc2136TestZone        = "example.com."
	rfc2136TestTsigKeyName = "example.com."
	rfc2136TestTTL         = 60
	rfc2136TestTsigSecret  = "IwBTJx9wrDp4Y1RyC3H0gA=="
)

func TestRFC2136CanaryLocalTestServer(t *testing.T) {
	dns.HandleFunc("example.com.", serverHandlerHello)
	defer dns.HandleRemove("example.com.")

	server, addrstr, err := runLocalDNSTestServer("127.0.0.1:0", false)
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Shutdown()

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeTXT)
	r, _, err := c.Exchange(m, addrstr)
	if err != nil || len(r.Extra) == 0 {
		t.Fatalf("Failed to communicate with test server: %v", err)
	}
	txt := r.Extra[0].(*dns.TXT).Txt[0]
	if txt != "Hello world" {
		t.Error("Expected test server to return 'Hello world' but got: ", txt)
	}
}

func TestRFC2136ServerSuccess(t *testing.T) {
	dns.HandleFunc(rfc2136TestZone, serverHandlerReturnSuccess)
	defer dns.HandleRemove(rfc2136TestZone)

	server, addrstr, err := runLocalDNSTestServer("127.0.0.1:0", false)

	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Shutdown()

	provider, err := NewDNSProviderCredentials(addrstr, "", "", "", util.RecursiveNameservers)
	if err != nil {
		t.Fatalf("Expected NewDNSProviderCredentials() to return no error but the error was -> %v", err)
	}
	if err := provider.Present(rfc2136TestDomain, "_acme-challenge."+rfc2136TestDomain+".", rfc2136TestKeyAuth); err != nil {
		t.Errorf("Expected Present() to return no error but the error was -> %v", err)
	}
}

func TestRFC2136ServerError(t *testing.T) {
	dns.HandleFunc(rfc2136TestZone, serverHandlerReturnErr)
	defer dns.HandleRemove(rfc2136TestZone)

	server, addrstr, err := runLocalDNSTestServer("127.0.0.1:0", false)
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Shutdown()

	provider, err := NewDNSProviderCredentials(addrstr, "", "", "", util.RecursiveNameservers)
	if err != nil {
		t.Fatalf("Expected NewDNSProviderCredentials() to return no error but the error was -> %v", err)
	}
	if err := provider.Present(rfc2136TestDomain, "_acme-challenge."+rfc2136TestDomain+".", rfc2136TestKeyAuth); err == nil {
		t.Errorf("Expected Present() to return an error but it did not.")
	} else if !strings.Contains(err.Error(), "NOTZONE") {
		t.Errorf("Expected Present() to return an error with the 'NOTZONE' rcode string but it did not.")
	}
}

func TestRFC2136TsigClient(t *testing.T) {
	dns.HandleFunc(rfc2136TestZone, serverHandlerReturnSuccess)
	defer dns.HandleRemove(rfc2136TestZone)

	server, addrstr, err := runLocalDNSTestServer("127.0.0.1:0", true)
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Shutdown()

	provider, err := NewDNSProviderCredentials(addrstr, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	if err != nil {
		t.Fatalf("Expected NewDNSProviderCredentials() to return no error but the error was -> %v", err)
	}
	if err := provider.Present(rfc2136TestDomain, "_acme-challenge."+rfc2136TestDomain+".", rfc2136TestKeyAuth); err != nil {
		t.Errorf("Expected Present() to return no error but the error was -> %v", err)
	}
}

func TestRFC2136InvalidNameserverFQDN(t *testing.T) {
	_, err := NewDNSProviderCredentials("nameserver.com", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	assert.Error(t, err)
}

func TestRFC2136InvalidNameserverFQDNWithPort(t *testing.T) {
	_, err := NewDNSProviderCredentials("nameserver.com:53", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	assert.Error(t, err)
}

func TestRFC2136InvalidNameserverFQDNWithPort2(t *testing.T) {
	_, err := NewDNSProviderCredentials("nameserver.com:", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	assert.Error(t, err)
}

func TestRFC2136NamserverWithoutPort(t *testing.T) {
	nameserver := "127.0.0.1"
	dnsProvider, err := NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	assert.NoError(t, err)

	if dnsProvider.nameserver != nameserver+":"+defaultPort {
		t.Errorf("dnsProvider.namserver to be %v:%v, but it is %v", nameserver, defaultPort, dnsProvider.nameserver)
	}

}

func TestRFC2136NamserverWithoutPort2(t *testing.T) {
	nameserver := "127.0.0.1:"
	dnsProvider, err := NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	assert.NoError(t, err)

	if dnsProvider.nameserver != nameserver+defaultPort {
		t.Errorf("dnsProvider.namserver to be %v%v, but it is %v", nameserver, defaultPort, dnsProvider.nameserver)
	}
}

func TestRFC2136NamserverWithPort(t *testing.T) {
	nameserver := "127.0.0.1:12345"
	dnsProvider, err := NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	assert.NoError(t, err)

	if dnsProvider.nameserver != nameserver {
		t.Errorf("dnsProvider.namserver to be %v, but it is %v", nameserver, dnsProvider.nameserver)
	}
}

func TestRFC2136NamserverWithPortNoIP(t *testing.T) {
	_, err := NewDNSProviderCredentials(":53", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	assert.Error(t, err)
}

func TestRFC2136NamserverEmpty(t *testing.T) {
	_, err := NewDNSProviderCredentials("", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	assert.Error(t, err)
}

func TestRFC2136NamserverIPInvalid(t *testing.T) {
	_, err := NewDNSProviderCredentials("900.65.3.64", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	assert.Error(t, err)
}

func TestRFC2136NamserverIPInvalid2(t *testing.T) {
	_, err := NewDNSProviderCredentials(":", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	assert.Error(t, err)
}
func TestRFC2136DefaultTSIGAlgorithm(t *testing.T) {
	provider, err := NewDNSProviderCredentials("127.0.0.1:0", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	if err != nil {
		assert.Equal(t, provider.tsigAlgorithm, dns.HmacMD5, "Default TSIG must match")
	}
}

func TestRFC2136InvalidTSIGAlgorithm(t *testing.T) {
	_, err := NewDNSProviderCredentials("127.0.0.1:0", "HAMMOCK", rfc2136TestTsigKeyName, rfc2136TestTsigSecret, util.RecursiveNameservers)
	assert.Error(t, err)
}

func TestRFC2136ValidUpdatePacket(t *testing.T) {
	dns.HandleFunc(rfc2136TestZone, (&basicStatefulServer{}).serverHandlerPassBackRequest)
	defer dns.HandleRemove(rfc2136TestZone)

	server, addrstr, err := runLocalDNSTestServer("127.0.0.1:0", false)
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Shutdown()

	txtRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", rfc2136TestFqdn, rfc2136TestTTL, rfc2136TestValue))
	rrs := []dns.RR{txtRR}
	m := new(dns.Msg)
	m.SetUpdate(rfc2136TestZone)
	m.RemoveRRset(rrs)
	m.Insert(rrs)
	//expectstr := m.String()
	//expect, err := m.Pack()
	if err != nil {
		t.Fatalf("Error packing expect msg: %v", err)
	}

	provider, err := NewDNSProviderCredentials(addrstr, "", "", "", util.RecursiveNameservers)
	if err != nil {
		t.Fatalf("Expected NewDNSProviderCredentials() to return no error but the error was -> %v", err)
	}

	if err := provider.Present(rfc2136TestDomain, "_acme-challenge."+rfc2136TestDomain+".", rfc2136TestValue); err != nil {
		t.Errorf("Expected Present() to return no error but the error was -> %v", err)
	}

	assert.NoError(t, err)
}

func runLocalDNSTestServer(listenAddr string, tsig bool) (*dns.Server, string, error) {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, "", err
	}
	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Hour, WriteTimeout: time.Hour}
	if tsig {
		server.TsigSecret = map[string]string{rfc2136TestTsigKeyName: rfc2136TestTsigSecret}
	}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	go func() {
		server.ActivateAndServe()
		pc.Close()
	}()

	waitLock.Lock()
	return server, pc.LocalAddr().String(), nil
}

func serverHandlerHello(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = &dns.TXT{
		Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{"Hello world"},
	}
	w.WriteMsg(m)
}

func serverHandlerReturnSuccess(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	if req.Opcode == dns.OpcodeQuery && req.Question[0].Qtype == dns.TypeSOA && req.Question[0].Qclass == dns.ClassINET {
		// Return SOA to appease findZoneByFqdn()
		soaRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN SOA ns1.%s admin.%s 2016022801 28800 7200 2419200 1200", rfc2136TestZone, rfc2136TestTTL, rfc2136TestZone, rfc2136TestZone))
		m.Answer = []dns.RR{soaRR}
	}

	if t := req.IsTsig(); t != nil {
		if w.TsigStatus() == nil {
			// Validated
			m.SetTsig(rfc2136TestZone, dns.HmacMD5, 300, time.Now().Unix())
		}
	}

	w.WriteMsg(m)
}

func serverHandlerReturnErr(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNotZone)
	w.WriteMsg(m)
}

type basicStatefulServer struct {
	txtRecords map[string][]string
}

func (b *basicStatefulServer) serverHandlerPassBackRequest(w dns.ResponseWriter, req *dns.Msg) {
	if b.txtRecords == nil {
		b.txtRecords = make(map[string][]string)
	}

	m := new(dns.Msg)
	m.SetReply(req)
	defer w.WriteMsg(m)

	if t := req.IsTsig(); t != nil {
		if w.TsigStatus() == nil {
			// Validated
			m.SetTsig(rfc2136TestZone, dns.HmacMD5, 300, time.Now().Unix())
		}
	}

	if (req.Opcode != dns.OpcodeUpdate && req.Opcode != dns.OpcodeQuery) || req.Question[0].Qclass != dns.ClassINET {
		klog.Infof("skipping dns packet: %#v", req)
		//m.Rcode = dns.RcodeServerFailure
		return
	}

	if req.Opcode == dns.OpcodeUpdate {
		for _, rr := range req.Ns {
			txt := rr.(*dns.TXT)
			if rr.Header().Class == dns.ClassNONE {
				klog.Infof("deleting val %q", txt.Hdr.Name)
				delete(b.txtRecords, txt.Hdr.Name)
				continue
			}
			klog.Infof("setting value %q: %v", txt.Hdr.Name, txt.Txt)
			b.txtRecords[txt.Hdr.Name] = txt.Txt
		}
	}

	switch req.Question[0].Qtype {
	case dns.TypeSOA:
		// Return SOA to appease findZoneByFqdn()
		soaRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN SOA ns1.%s admin.%s 2016022801 28800 7200 2419200 1200", rfc2136TestZone, rfc2136TestTTL, rfc2136TestZone, rfc2136TestZone))
		m.Answer = []dns.RR{soaRR}
	case dns.TypeTXT:
		for _, rr := range b.txtRecords[req.Question[0].Name] {
			klog.Infof("returning %q", fmt.Sprintf("%s %d IN TXT %s", req.Question[0].Name, rfc2136TestTTL, rr))
			txtRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", req.Question[0].Name, rfc2136TestTTL, rr))
			m.Answer = append(m.Answer, txtRR)
		}
	}
}
