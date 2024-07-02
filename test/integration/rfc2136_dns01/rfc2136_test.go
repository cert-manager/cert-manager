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
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	logtesting "github.com/go-logr/logr/testing"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/rfc2136"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	testserver "github.com/cert-manager/cert-manager/test/acme/server"
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

const defaultPort = "53"

func TestRFC2136CanaryLocalTestServer(t *testing.T) {
	ctx := logf.NewContext(context.TODO(), logtesting.NewTestLogger(t), t.Name())
	server := &testserver.BasicServer{
		T:       t,
		Zones:   []string{rfc2136TestZone},
		Handler: dns.HandlerFunc((&testHandlers{t: t}).serverHandlerHello),
	}
	if err := server.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer func() {
		require.NoError(t, server.Shutdown())
	}()

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeTXT)
	r, _, err := c.Exchange(m, server.ListenAddr())
	if err != nil || len(r.Extra) == 0 {
		t.Fatalf("Failed to communicate with test server: %v", err)
	}
	txt := r.Extra[0].(*dns.TXT).Txt[0]
	if txt != "Hello world" {
		t.Error("Expected test server to return 'Hello world' but got: ", txt)
	}
}

func TestRFC2136ServerSuccess(t *testing.T) {
	ctx := logf.NewContext(context.TODO(), logtesting.NewTestLogger(t), t.Name())
	server := &testserver.BasicServer{
		T:       t,
		Zones:   []string{rfc2136TestZone},
		Handler: dns.HandlerFunc((&testHandlers{t: t}).serverHandlerReturnSuccess),
	}
	if err := server.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer func() {
		if err := server.Shutdown(); err != nil {
			t.Fatalf("failed to shutdown test server: %v", err)
		}
	}()

	provider, err := rfc2136.NewDNSProviderCredentials(server.ListenAddr(), "", "", "")
	if err != nil {
		t.Fatalf("Expected rfc2136.NewDNSProviderCredentials() to return no error but the error was -> %v", err)
	}
	if err := provider.Present(rfc2136TestDomain, "_acme-challenge."+rfc2136TestDomain+".", rfc2136TestDomain+".", rfc2136TestKeyAuth); err != nil {
		t.Errorf("Expected Present() to return no error but the error was -> %v", err)
	}
}

func TestRFC2136ServerError(t *testing.T) {
	ctx := logf.NewContext(context.TODO(), logtesting.NewTestLogger(t), t.Name())
	server := &testserver.BasicServer{
		T:       t,
		Zones:   []string{rfc2136TestZone},
		Handler: dns.HandlerFunc((&testHandlers{t: t}).serverHandlerReturnErr),
	}
	if err := server.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer func() {
		if err := server.Shutdown(); err != nil {
			t.Fatalf("failed to shutdown test server: %v", err)
		}
	}()

	provider, err := rfc2136.NewDNSProviderCredentials(server.ListenAddr(), "", "", "")
	if err != nil {
		t.Fatalf("Expected rfc2136.NewDNSProviderCredentials() to return no error but the error was -> %v", err)
	}
	if err := provider.Present(rfc2136TestDomain, "_acme-challenge."+rfc2136TestDomain+".", rfc2136TestDomain+".", rfc2136TestKeyAuth); err == nil {
		t.Errorf("Expected Present() to return an error but it did not.")
	} else if !strings.Contains(err.Error(), "NOTZONE") {
		t.Errorf("Expected Present() to return an error with the 'NOTZONE' rcode string but it did not.")
	}
}

func TestRFC2136TsigClient(t *testing.T) {
	ctx := logf.NewContext(context.TODO(), logtesting.NewTestLogger(t), t.Name())
	server := &testserver.BasicServer{
		T:             t,
		Zones:         []string{rfc2136TestZone},
		Handler:       dns.HandlerFunc((&testHandlers{t: t}).serverHandlerReturnSuccess),
		EnableTSIG:    true,
		TSIGZone:      rfc2136TestZone,
		TSIGKeyName:   rfc2136TestTsigKeyName,
		TSIGKeySecret: rfc2136TestTsigSecret,
	}
	if err := server.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer func() {
		if err := server.Shutdown(); err != nil {
			t.Fatalf("failed to shutdown test server: %v", err)
		}
	}()

	provider, err := rfc2136.NewDNSProviderCredentials(server.ListenAddr(), "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	if err != nil {
		t.Fatalf("Expected rfc2136.NewDNSProviderCredentials() to return no error but the error was -> %v", err)
	}
	if err := provider.Present(rfc2136TestDomain, "_acme-challenge."+rfc2136TestDomain+".", rfc2136TestDomain+".", rfc2136TestKeyAuth); err != nil {
		t.Errorf("Expected Present() to return no error but the error was -> %v", err)
	}
}

func TestRFC2136NameserverEmpty(t *testing.T) {
	_, err := rfc2136.NewDNSProviderCredentials("", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.Error(t, err)
}

func TestRFC2136NameserverWithoutHost(t *testing.T) {
	_, err := rfc2136.NewDNSProviderCredentials(":53", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.Error(t, err)
}

func TestRFC2136NameserverWithoutHostNorPort(t *testing.T) {
	_, err := rfc2136.NewDNSProviderCredentials(":", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.Error(t, err)
}

func TestRFC2136NameserverIPv4WithoutPort(t *testing.T) {
	nameserver := "127.0.0.1"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver+":"+defaultPort {
		t.Errorf("dnsProvider.Nameserver() to be %v:%v, but it is %v", nameserver, defaultPort, dnsProvider.Nameserver())
	}

}

func TestRFC2136NameserverIPv4WithEmptyPort(t *testing.T) {
	nameserver := "127.0.0.1:"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver+defaultPort {
		t.Errorf("dnsProvider.Nameserver() to be %v%v, but it is %v", nameserver, defaultPort, dnsProvider.Nameserver())
	}
}

func TestRFC2136NameserverIPv4WithPort(t *testing.T) {
	nameserver := "127.0.0.1:12345"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver {
		t.Errorf("dnsProvider.Nameserver() to be %v, but it is %v", nameserver, dnsProvider.Nameserver())
	}
}

func TestRFC2136NameserverIPv6NotEnclosed(t *testing.T) {
	nameserver := "2001:db8::1"
	_, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.Error(t, err)
}

func TestRFC2136NameserverIPv6Empty(t *testing.T) {
	nameserver := "[]:53"
	_, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.Error(t, err)
}

func TestRFC2136NameserverIPv6WithoutPort(t *testing.T) {
	nameserver := "[2001:db8::1]"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver+":"+defaultPort {
		t.Errorf("dnsProvider.Nameserver() to be %v:%v, but it is %v", nameserver, defaultPort, dnsProvider.Nameserver())
	}
}

func TestRFC2136NameserverIPv6WithEmptyPort(t *testing.T) {
	nameserver := "[2001:db8::1]:"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver+defaultPort {
		t.Errorf("dnsProvider.Nameserver() to be %v%v, but it is %v", nameserver, defaultPort, dnsProvider.Nameserver())
	}
}

func TestRFC2136NameserverIPv6WithPort(t *testing.T) {
	nameserver := "[2001:db8::1]:12345"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver {
		t.Errorf("dnsProvider.Nameserver() to be %v, but it is %v", nameserver, dnsProvider.Nameserver())
	}
}

func TestRFC2136NameserverFQDNWithoutPort(t *testing.T) {
	nameserver := "dns.example.net"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver+":"+defaultPort {
		t.Errorf("dnsProvider.Nameserver() to be %v, but it is %v", nameserver+":"+defaultPort, dnsProvider.Nameserver())
	}
}

func TestRFC2136NameserverFQDNWithEmptyPort(t *testing.T) {
	nameserver := "dns.example.com:"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver+defaultPort {
		t.Errorf("dnsProvider.Nameserver() to be %v%v, but it is %v", nameserver, defaultPort, dnsProvider.Nameserver())
	}
}

func TestRFC2136NameserverFQDNWithPort(t *testing.T) {
	nameserver := "dns.example.net:12345"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver {
		t.Errorf("dnsProvider.Nameserver() to be %v, but it is %v", nameserver, dnsProvider.Nameserver())
	}
}

func TestRFC2136NameserverHostnameWithoutPort(t *testing.T) {
	nameserver := "dns"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver+":"+defaultPort {
		t.Errorf("dnsProvider.Nameserver() to be %v, but it is %v", nameserver+":"+defaultPort, dnsProvider.Nameserver())
	}
}

func TestRFC2136NameserverHostnameWithEmptyPort(t *testing.T) {
	nameserver := "dns:"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver+defaultPort {
		t.Errorf("dnsProvider.Nameserver() to be %v%v, but it is %v", nameserver, defaultPort, dnsProvider.Nameserver())
	}
}

func TestRFC2136NameserverHostnameWithPort(t *testing.T) {
	nameserver := "dns:12345"
	dnsProvider, err := rfc2136.NewDNSProviderCredentials(nameserver, "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.NoError(t, err)

	if dnsProvider.Nameserver() != nameserver {
		t.Errorf("dnsProvider.Nameserver() to be %v, but it is %v", nameserver, dnsProvider.Nameserver())
	}
}

func TestRFC2136DefaultTSIGAlgorithm(t *testing.T) {
	provider, err := rfc2136.NewDNSProviderCredentials("127.0.0.1:0", "", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	if err != nil {
		assert.Equal(t, provider.TSIGAlgorithm(), dns.HmacMD5, "Default TSIG must match")
	}
}

func TestRFC2136InvalidTSIGAlgorithm(t *testing.T) {
	_, err := rfc2136.NewDNSProviderCredentials("127.0.0.1:0", "HAMMOCK", rfc2136TestTsigKeyName, rfc2136TestTsigSecret)
	assert.Error(t, err)
}

func TestRFC2136ValidUpdatePacket(t *testing.T) {
	ctx := logf.NewContext(context.TODO(), logtesting.NewTestLogger(t), t.Name())
	server := &testserver.BasicServer{
		T:     t,
		Zones: []string{rfc2136TestZone},
	}
	if err := server.Run(ctx); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer func() {
		if err := server.Shutdown(); err != nil {
			t.Errorf("failed to gracefully shut down test server: %v", err)
		}
	}()

	txtRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", rfc2136TestFqdn, rfc2136TestTTL, rfc2136TestValue))
	rrs := []dns.RR{txtRR}
	m := new(dns.Msg)
	m.SetUpdate(rfc2136TestZone)
	m.RemoveRRset(rrs)
	m.Insert(rrs)

	provider, err := rfc2136.NewDNSProviderCredentials(server.ListenAddr(), "", "", "")
	if err != nil {
		t.Fatalf("Expected rfc2136.NewDNSProviderCredentials() to return no error but the error was -> %v", err)
	}

	if err := provider.Present(rfc2136TestDomain, "_acme-challenge."+rfc2136TestDomain+".", rfc2136TestDomain+".", rfc2136TestValue); err != nil {
		t.Errorf("Expected Present() to return no error but the error was -> %v", err)
	}

	assert.NoError(t, err)
}

// testHandlers provides DNS server handlers for use in tests and has a
// reference to testing.T so that the handlers (which do not return errors) can
// make test assertions and fail tests.
type testHandlers struct {
	t *testing.T
}

func (o *testHandlers) serverHandlerHello(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = &dns.TXT{
		Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{"Hello world"},
	}
	if err := w.WriteMsg(m); err != nil {
		assert.NoError(o.t, err)
	}
}

func (o *testHandlers) serverHandlerReturnSuccess(w dns.ResponseWriter, req *dns.Msg) {
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
	if err := w.WriteMsg(m); err != nil {
		assert.NoError(o.t, err)
	}
}

func (o *testHandlers) serverHandlerReturnErr(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNotZone)
	if err := w.WriteMsg(m); err != nil {
		assert.NoError(o.t, err)
	}
}
