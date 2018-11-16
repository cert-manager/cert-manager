package rfc2136

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenolf/lego/acme"
)

var (
	envTestDomain     = "123456789.www.example.com"
	envTestKeyAuth    = "123d=="
	envTestValue      = "Now36o-3BmlB623-0c1qCIUmgWVVmDJb88KGl24pqpo"
	envTestFqdn       = "_acme-challenge.123456789.www.example.com."
	envTestZone       = "example.com."
	envTestTTL        = 120
	envTestTsigKey    = "example.com."
	envTestTsigSecret = "IwBTJx9wrDp4Y1RyC3H0gA=="
)

var reqChan = make(chan *dns.Msg, 10)

func TestCanaryLocalTestServer(t *testing.T) {
	acme.ClearFqdnCache()
	dns.HandleFunc("example.com.", serverHandlerHello)
	defer dns.HandleRemove("example.com.")

	server, addr, err := runLocalDNSTestServer(false)
	require.NoError(t, err, "Failed to start test server")
	defer func() { _ = server.Shutdown() }()

	c := new(dns.Client)
	m := new(dns.Msg)

	m.SetQuestion("example.com.", dns.TypeTXT)

	r, _, err := c.Exchange(m, addr)
	require.NoError(t, err, "Failed to communicate with test server")
	assert.Len(t, r.Extra, 1, "Failed to communicate with test server")

	txt := r.Extra[0].(*dns.TXT).Txt[0]
	assert.Equal(t, "Hello world", txt)
}

func TestServerSuccess(t *testing.T) {
	acme.ClearFqdnCache()
	dns.HandleFunc(envTestZone, serverHandlerReturnSuccess)
	defer dns.HandleRemove(envTestZone)

	server, addr, err := runLocalDNSTestServer(false)
	require.NoError(t, err, "Failed to start test server")
	defer func() { _ = server.Shutdown() }()

	config := NewDefaultConfig()
	config.Nameserver = addr

	provider, err := NewDNSProviderConfig(config)
	require.NoError(t, err)

	err = provider.Present(envTestDomain, "", envTestKeyAuth)
	require.NoError(t, err)
}

func TestServerError(t *testing.T) {
	acme.ClearFqdnCache()
	dns.HandleFunc(envTestZone, serverHandlerReturnErr)
	defer dns.HandleRemove(envTestZone)

	server, addr, err := runLocalDNSTestServer(false)
	require.NoError(t, err, "Failed to start test server")
	defer func() { _ = server.Shutdown() }()

	config := NewDefaultConfig()
	config.Nameserver = addr

	provider, err := NewDNSProviderConfig(config)
	require.NoError(t, err)

	err = provider.Present(envTestDomain, "", envTestKeyAuth)
	require.Error(t, err)
	if !strings.Contains(err.Error(), "NOTZONE") {
		t.Errorf("Expected Present() to return an error with the 'NOTZONE' rcode string but it did not: %v", err)
	}
}

func TestTsigClient(t *testing.T) {
	acme.ClearFqdnCache()
	dns.HandleFunc(envTestZone, serverHandlerReturnSuccess)
	defer dns.HandleRemove(envTestZone)

	server, addr, err := runLocalDNSTestServer(true)
	require.NoError(t, err, "Failed to start test server")
	defer func() { _ = server.Shutdown() }()

	config := NewDefaultConfig()
	config.Nameserver = addr
	config.TSIGKey = envTestTsigKey
	config.TSIGSecret = envTestTsigSecret

	provider, err := NewDNSProviderConfig(config)
	require.NoError(t, err)

	err = provider.Present(envTestDomain, "", envTestKeyAuth)
	require.NoError(t, err)
}

func TestValidUpdatePacket(t *testing.T) {
	acme.ClearFqdnCache()
	dns.HandleFunc(envTestZone, serverHandlerPassBackRequest)
	defer dns.HandleRemove(envTestZone)

	server, addr, err := runLocalDNSTestServer(false)
	require.NoError(t, err, "Failed to start test server")
	defer func() { _ = server.Shutdown() }()

	txtRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", envTestFqdn, envTestTTL, envTestValue))
	rrs := []dns.RR{txtRR}
	m := new(dns.Msg)
	m.SetUpdate(envTestZone)
	m.RemoveRRset(rrs)
	m.Insert(rrs)
	expectStr := m.String()

	expect, err := m.Pack()
	require.NoError(t, err, "error packing")

	config := NewDefaultConfig()
	config.Nameserver = addr

	provider, err := NewDNSProviderConfig(config)
	require.NoError(t, err)

	err = provider.Present(envTestDomain, "", "1234d==")
	require.NoError(t, err)

	rcvMsg := <-reqChan
	rcvMsg.Id = m.Id

	actual, err := rcvMsg.Pack()
	require.NoError(t, err, "error packing")

	if !bytes.Equal(actual, expect) {
		tmp := new(dns.Msg)
		if err := tmp.Unpack(actual); err != nil {
			t.Fatalf("Error unpacking actual msg: %v", err)
		}
		t.Errorf("Expected msg:\n%s", expectStr)
		t.Errorf("Actual msg:\n%v", tmp)
	}
}

func runLocalDNSTestServer(tsig bool) (*dns.Server, string, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}

	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Hour, WriteTimeout: time.Hour}
	if tsig {
		server.TsigSecret = map[string]string{envTestTsigKey: envTestTsigSecret}
	}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	go func() {
		_ = server.ActivateAndServe()
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
	_ = w.WriteMsg(m)
}

func serverHandlerReturnSuccess(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	if req.Opcode == dns.OpcodeQuery && req.Question[0].Qtype == dns.TypeSOA && req.Question[0].Qclass == dns.ClassINET {
		// Return SOA to appease findZoneByFqdn()
		soaRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN SOA ns1.%s admin.%s 2016022801 28800 7200 2419200 1200", envTestZone, envTestTTL, envTestZone, envTestZone))
		m.Answer = []dns.RR{soaRR}
	}

	if t := req.IsTsig(); t != nil {
		if w.TsigStatus() == nil {
			// Validated
			m.SetTsig(envTestZone, dns.HmacMD5, 300, time.Now().Unix())
		}
	}

	_ = w.WriteMsg(m)
}

func serverHandlerReturnErr(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNotZone)
	_ = w.WriteMsg(m)
}

func serverHandlerPassBackRequest(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	if req.Opcode == dns.OpcodeQuery && req.Question[0].Qtype == dns.TypeSOA && req.Question[0].Qclass == dns.ClassINET {
		// Return SOA to appease findZoneByFqdn()
		soaRR, _ := dns.NewRR(fmt.Sprintf("%s %d IN SOA ns1.%s admin.%s 2016022801 28800 7200 2419200 1200", envTestZone, envTestTTL, envTestZone, envTestZone))
		m.Answer = []dns.RR{soaRR}
	}

	if t := req.IsTsig(); t != nil {
		if w.TsigStatus() == nil {
			// Validated
			m.SetTsig(envTestZone, dns.HmacMD5, 300, time.Now().Unix())
		}
	}

	_ = w.WriteMsg(m)
	if req.Opcode != dns.OpcodeQuery || req.Question[0].Qtype != dns.TypeSOA || req.Question[0].Qclass != dns.ClassINET {
		// Only talk back when it is not the SOA RR.
		reqChan <- req
	}
}
