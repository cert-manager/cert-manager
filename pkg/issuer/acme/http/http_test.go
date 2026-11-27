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

package http

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"k8s.io/client-go/rest"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
)

// countReachabilityTestCalls is a wrapper function that allows us to count the number
// of calls to a reachabilityTest.
func countReachabilityTestCalls(counter *int, t reachabilityTest) reachabilityTest {
	return func(ctx context.Context, url *url.URL, key string, dnsServers []string, userAgent string) error {
		*counter++
		return t(ctx, url, key, dnsServers, userAgent)
	}
}

func TestCheck(t *testing.T) {
	type testT struct {
		name             string
		reachabilityTest reachabilityTest
		challenge        *cmacme.Challenge
		expectedErr      bool
	}
	tests := []testT{
		{
			name: "should pass",
			reachabilityTest: func(context.Context, *url.URL, string, []string, string) error {
				return nil
			},
			expectedErr: false,
		},
		{
			name: "should error",
			reachabilityTest: func(context.Context, *url.URL, string, []string, string) error {
				return fmt.Errorf("failed")
			},
			expectedErr: true,
		},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			requiredCallsForPass := 2
			if test.challenge == nil {
				test.challenge = &cmacme.Challenge{}
			}
			s := Solver{
				Context:          &controller.Context{RESTConfig: new(rest.Config)},
				testReachability: countReachabilityTestCalls(&calls, test.reachabilityTest),
				requiredPasses:   requiredCallsForPass,
			}

			err := s.Check(t.Context(), nil, test.challenge)
			if err != nil && !test.expectedErr {
				t.Errorf("Expected Check to return non-nil error, but got %v", err)
				return
			}
			if err == nil && test.expectedErr {
				t.Errorf("Expected error from Check, but got none")
				return
			}
			if !test.expectedErr && calls != requiredCallsForPass {
				t.Errorf("Expected Wait to verify reachability test passes %d times, but only checked %d", requiredCallsForPass, calls)
				return
			}
		})
	}
}

func TestCheckStopsSleepingWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	s := Solver{
		Context: &controller.Context{RESTConfig: new(rest.Config)},
		testReachability: countReachabilityTestCalls(&calls, func(context.Context, *url.URL, string, []string, string) error {
			cancel()
			return nil
		}),
		requiredPasses: 2,
	}

	start := time.Now()
	err := s.Check(ctx, nil, &cmacme.Challenge{})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 reachability call, got %d", calls)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Errorf("Check slept through the cancelled context for %s", elapsed)
	}
}

func TestReachabilityCustomDnsServers(t *testing.T) {
	site := "https://cert-manager.io"
	u, err := url.Parse(site)
	if err != nil {
		t.Fatalf("Failed to parse url %s: %v", site, err)
	}
	ips, err := net.LookupIP(u.Host) //nolint: noctx // We intentionally use LookupIP here for test compatibility
	if err != nil {
		t.Fatalf("Failed to resolve %s: %v", u.Host, err)
	}

	handleDNS := func(called *int32) func(dns.ResponseWriter, *dns.Msg) {
		return func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)

			if r.Opcode != dns.OpcodeQuery {
				return
			}
			for _, q := range m.Question {
				if q.Name != u.Host+"." {
					continue
				}
				switch q.Qtype {
				case dns.TypeA:
					t.Logf("A Query for %s\n", q.Name)
					atomic.StoreInt32(called, 1)
					for _, ip := range ips {
						if strings.Contains(ip.String(), ":") {
							continue
						}
						rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
						if err == nil {
							m.Answer = append(m.Answer, rr)
						}
					}
				case dns.TypeAAAA:
					t.Logf("AAAA Query for %s\n", q.Name)
					atomic.StoreInt32(called, 1)
					for _, ip := range ips {
						if !strings.Contains(ip.String(), ":") {
							continue
						}
						rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, ip))
						if err == nil {
							m.Answer = append(m.Answer, rr)
						}
					}
				}
			}
			if err := w.WriteMsg(m); err != nil {
				t.Errorf("failed to write DNS response: %v", err)
			}
		}
	}

	dnsServerStarted := make(chan struct{})
	dnsServerCalled := int32(0)

	server := &dns.Server{Addr: "127.0.0.1:15353", Net: "udp", NotifyStartedFunc: func() { close(dnsServerStarted) }}
	defer func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
	}()

	mux := &dns.ServeMux{}
	server.Handler = mux
	mux.HandleFunc(".", handleDNS(&dnsServerCalled))

	go func() {
		if err := server.ListenAndServe(); err != nil {
			t.Error(err)
		}
	}()

	dnsServer2Started := make(chan struct{})
	dnsServer2Called := int32(0)

	server2 := &dns.Server{Addr: "127.0.0.1:15354", Net: "udp", NotifyStartedFunc: func() { close(dnsServer2Started) }}
	defer func() {
		if err := server2.Shutdown(); err != nil {
			t.Error(err)
		}
	}()

	mux2 := &dns.ServeMux{}
	server2.Handler = mux2
	mux2.HandleFunc(".", handleDNS(&dnsServer2Called))

	go func() {
		if err := server2.ListenAndServe(); err != nil {
			t.Error(err)
		}
	}()

	// Wait for both servers to have started
	<-dnsServerStarted
	<-dnsServer2Started

	key := "there is no key"

	tests := []struct {
		name             string
		dnsServers       []string
		dnsServer1Called bool
		dnsServer2Called bool
	}{
		{
			name:             "custom dns servers",
			dnsServers:       []string{"127.0.0.1:15353"},
			dnsServer1Called: true,
			dnsServer2Called: false,
		},
		{
			// The servers are tried in order and the first one answers, so the
			// second is never reached.
			name:             "two custom dns servers",
			dnsServers:       []string{"127.0.0.1:15353", "127.0.0.1:15354"},
			dnsServer1Called: true,
			dnsServer2Called: false,
		},
		{
			name:             "system dns servers",
			dnsServer1Called: false,
			dnsServer2Called: false,
		},
	}

	for _, tt := range tests {
		atomic.StoreInt32(&dnsServerCalled, 0)
		atomic.StoreInt32(&dnsServer2Called, 0)
		err = testReachability(t.Context(), u, key, tt.dnsServers, "cert-manager-test")
		switch {
		case err == nil:
			t.Errorf("Expected error for testReachability, but got none")
		case strings.Contains(err.Error(), key):
			called1 := atomic.LoadInt32(&dnsServerCalled) == 1
			called2 := atomic.LoadInt32(&dnsServer2Called) == 1
			if called1 != tt.dnsServer1Called {
				t.Errorf("Expected DNS server 1 called: %v, but got %v", tt.dnsServer1Called, called1)
			}
			if called2 != tt.dnsServer2Called {
				t.Errorf("Expected DNS server 2 called: %v, but got %v", tt.dnsServer2Called, called2)
			}
		default:
			t.Errorf("Unexpected error: %v", err)
		}
	}
}

// errorLeaksBody reports whether err's message contains body.
func errorLeaksBody(err error, body string) bool {
	return strings.Contains(strings.ToLower(err.Error()), strings.ToLower(body))
}

// maxUntruncatedBodyLen is the length the old (removed) code truncated the
// reflected body to. A sentinel has to be shorter than this for the tests to be
// an effective regression test for the future: otherwise the old code would
// only have leaked a prefix and the tests would pass against it too.
// assertEffectiveSentinel enforces this.
const maxUntruncatedBodyLen = 24

func assertEffectiveSentinel(t *testing.T, sentinel string) {
	t.Helper()
	if len(sentinel) > maxUntruncatedBodyLen {
		t.Fatalf("sentinel %q is %d chars; it must be <= %d to be an effective regression test", sentinel, len(sentinel), maxUntruncatedBodyLen)
	}
}

// TestReachabilityDoesNotReflectResponseBody ensures that when the endpoint
// returns a body that does not match the expected key, the contents of that
// body are not included in the returned error.
func TestReachabilityDoesNotReflectResponseBody(t *testing.T) {
	const responseBody = "SENTINEL-BODY"
	const key = "the-expected-challenge-key"
	assertEffectiveSentinel(t, responseBody)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, responseBody)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL %q: %v", server.URL, err)
	}

	err = testReachability(t.Context(), u, key, nil, "cert-manager-test")
	if err == nil {
		t.Fatal("expected testReachability to return an error for a mismatched response, but got none")
	}
	if errorLeaksBody(err, responseBody) {
		t.Errorf("expected error not to contain the response body %q, but it did: %v", responseBody, err)
	}
}

// TestReachabilityDoesNotReflectRedirectedResponseBody ensures that a response
// body reached by following a redirect is not reflected in the returned error.
func TestReachabilityDoesNotReflectRedirectedResponseBody(t *testing.T) {
	const internalBody = "SENTINEL-REDIRECT"
	const key = "the-expected-challenge-key"
	assertEffectiveSentinel(t, internalBody)

	// internal represents an internal-only endpoint reachable from the
	// controller pod but not intended to be exposed to tenants.
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, internalBody)
	}))
	defer internal.Close()

	// public is the host being validated; it redirects the self-check to the
	// internal endpoint.
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer public.Close()

	u, err := url.Parse(public.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL %q: %v", public.URL, err)
	}

	err = testReachability(t.Context(), u, key, nil, "cert-manager-test")
	if err == nil {
		t.Fatal("expected testReachability to return an error, but got none")
	}
	if errorLeaksBody(err, internalBody) {
		t.Errorf("response body reached via a redirect must not be reflected in the error, but got: %v", err)
	}
}

// startDNSServer serves handler over UDP on a free loopback port, and over TCP
// on the same port when tcp is set, and returns the address.
func startDNSServer(t *testing.T, handler dns.HandlerFunc, tcp bool) string {
	t.Helper()
	var lc net.ListenConfig
	var tcpErr error
	// A free UDP port can be taken over TCP, so a clash retries on a new port.
	for range 5 {
		pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen for DNS over UDP: %v", err)
		}
		addr := pc.LocalAddr().String()
		if !tcp {
			runDNSServer(t, &dns.Server{PacketConn: pc, Handler: handler})
			return addr
		}
		l, err := lc.Listen(t.Context(), "tcp", addr)
		if err != nil {
			tcpErr = err
			pc.Close()
			continue
		}
		runDNSServer(t, &dns.Server{PacketConn: pc, Handler: handler})
		runDNSServer(t, &dns.Server{Listener: l, Handler: handler})
		return addr
	}
	t.Fatalf("failed to listen for DNS over TCP on the UDP port: %v", tcpErr)
	return ""
}

func runDNSServer(t *testing.T, server *dns.Server) {
	t.Helper()
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	errCh := make(chan error, 1)
	go func() { errCh <- server.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-errCh:
		t.Fatalf("DNS server did not start: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
	})
}

// answerHost replies to A and AAAA queries for challengeHost with the matching
// ips, as a recursive resolver would.
func answerHost(ips ...string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		for _, q := range r.Question {
			if q.Name != dns.Fqdn(challengeHost) {
				continue
			}
			for _, ip := range ips {
				rrType := "A"
				if strings.Contains(ip, ":") {
					rrType = "AAAA"
				}
				if dns.StringToType[rrType] != q.Qtype {
					continue
				}
				if rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", q.Name, rrType, ip)); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		_ = w.WriteMsg(m)
	}
}

func replyRcode(rcode int) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		_ = w.WriteMsg(m)
	}
}

const (
	challengeHost = "challenge.test"
	challengeKey  = "the-expected-challenge-key"
)

// startChallengeServer serves challengeKey on 127.0.0.1 and returns its URL
// under challengeHost, which therefore has to resolve to 127.0.0.1.
func startChallengeServer(t *testing.T) *url.URL {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, challengeKey)
	}))
	t.Cleanup(server.Close)

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to split the test server address: %v", err)
	}
	return &url.URL{Scheme: "http", Host: net.JoinHostPort(challengeHost, port), Path: "/"}
}

// TestReachabilityCustomDnsServersFailover ensures that a configured DNS server
// that cannot answer does not fail the self check when the next configured
// server can, and that a server that answers is not skipped.
func TestReachabilityCustomDnsServersFailover(t *testing.T) {
	tests := []struct {
		name    string
		first   dns.HandlerFunc
		wantErr bool
	}{
		{
			name:  "first server drops queries",
			first: func(dns.ResponseWriter, *dns.Msg) {},
		},
		{
			name:  "first server replies SERVFAIL",
			first: replyRcode(dns.RcodeServerFailure),
		},
		{
			name:  "first server replies REFUSED",
			first: replyRcode(dns.RcodeRefused),
		},
		{
			name: "first server does not recurse",
			first: func(w dns.ResponseWriter, r *dns.Msg) {
				m := new(dns.Msg)
				m.SetReply(r)
				_ = w.WriteMsg(m)
			},
		},
		{
			// NXDOMAIN is an answer, so the next server is not asked.
			name:    "first server replies NXDOMAIN",
			first:   replyRcode(dns.RcodeNameError),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := startChallengeServer(t)
			first := startDNSServer(t, tt.first, false)
			second := startDNSServer(t, answerHost("127.0.0.1"), false)

			err := testReachability(t.Context(), u, challengeKey, []string{first, second}, "cert-manager-test")
			if tt.wantErr && err == nil {
				t.Fatal("expected the self check to fail, but it succeeded")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected the self check to succeed through the second server, but got: %v", err)
			}
		})
	}
}

// TestReachabilityCustomDnsServersTruncated ensures that a truncated UDP reply
// is retried over TCP instead of being read as a name with no address.
func TestReachabilityCustomDnsServersTruncated(t *testing.T) {
	u := startChallengeServer(t)

	answer := answerHost("127.0.0.1")
	server := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		answer(w, r)
	}, true)

	if err := testReachability(t.Context(), u, challengeKey, []string{server}, "cert-manager-test"); err != nil {
		t.Errorf("expected the self check to succeed over TCP, but got: %v", err)
	}
}

// TestReachabilityCustomDnsServersEDNS0 ensures that queries carry an EDNS0
// record with a 1232 byte buffer size.
func TestReachabilityCustomDnsServersEDNS0(t *testing.T) {
	u := startChallengeServer(t)

	answer := answerHost("127.0.0.1")
	server := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if opt := r.IsEdns0(); opt == nil || opt.UDPSize() != 1232 {
			replyRcode(dns.RcodeFormatError)(w, r)
			return
		}
		answer(w, r)
	}, false)

	if err := testReachability(t.Context(), u, challengeKey, []string{server}, "cert-manager-test"); err != nil {
		t.Errorf("expected the self check to succeed with an EDNS0 query, but got: %v", err)
	}
}

// TestReachabilityCustomDnsServersAAAAFailure ensures that the A addresses of a
// server are used when its AAAA query fails.
func TestReachabilityCustomDnsServersAAAAFailure(t *testing.T) {
	u := startChallengeServer(t)

	answer := answerHost("127.0.0.1")
	server := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeAAAA {
			replyRcode(dns.RcodeServerFailure)(w, r)
			return
		}
		answer(w, r)
	}, false)

	if err := testReachability(t.Context(), u, challengeKey, []string{server}, "cert-manager-test"); err != nil {
		t.Errorf("expected the self check to succeed with the A address, but got: %v", err)
	}
}

// TestReachabilityCustomDnsServersTriesEveryAddress ensures that every address
// a server returns is tried, A and AAAA alike. The challenge listens on IPv4
// only, behind an IPv6 address that is tried first and cannot connect.
func TestReachabilityCustomDnsServersTriesEveryAddress(t *testing.T) {
	u := startChallengeServer(t)
	server := startDNSServer(t, answerHost("127.0.0.1", "::1"), false)

	var dialed []string
	original := dialContext
	dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return original(ctx, network, addr)
	}
	t.Cleanup(func() { dialContext = original })

	if err := testReachability(t.Context(), u, challengeKey, []string{server}, "cert-manager-test"); err != nil {
		t.Errorf("expected the self check to reach the IPv4 address, but got: %v", err)
	}
	want := []string{net.JoinHostPort("::1", u.Port()), net.JoinHostPort("127.0.0.1", u.Port())}
	if !slices.Equal(dialed, want) {
		t.Errorf("expected addresses to be dialed in order %v, but got %v", want, dialed)
	}
}

// TestDialAddresses ensures that IPv6 addresses are tried first and that one
// address that does not answer cannot use the whole dial timeout.
func TestDialAddresses(t *testing.T) {
	tests := []struct {
		name            string
		ips             []string
		wantOrder       []string
		wantFirstBudget time.Duration
	}{
		{
			name:            "IPv6 first, timeout shared between two addresses",
			ips:             []string{"192.0.2.1", "2001:db8::1"},
			wantOrder:       []string{"[2001:db8::1]:80", "192.0.2.1:80"},
			wantFirstBudget: dialTimeout / 2,
		},
		{
			name:            "each address keeps the minimum",
			ips:             []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"},
			wantOrder:       []string{"192.0.2.1:80", "192.0.2.2:80", "192.0.2.3:80", "192.0.2.4:80"},
			wantFirstBudget: minAddressDialTimeout,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var order []string
			var firstBudget time.Duration
			original := dialContext
			dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if len(order) == 0 {
					deadline, _ := ctx.Deadline()
					firstBudget = time.Until(deadline)
				}
				order = append(order, addr)
				return nil, errors.New("connection refused")
			}
			t.Cleanup(func() { dialContext = original })

			if _, err := dialAddresses(t.Context(), "tcp", "80", test.ips); err == nil {
				t.Fatal("expected an error when no address accepts")
			}
			if !slices.Equal(order, test.wantOrder) {
				t.Errorf("expected addresses to be tried in order %v, but got %v", test.wantOrder, order)
			}
			if firstBudget > test.wantFirstBudget || firstBudget < test.wantFirstBudget-100*time.Millisecond {
				t.Errorf("expected the first address to get about %v, but got %v", test.wantFirstBudget, firstBudget)
			}
		})
	}
}

// TestReachabilityCustomDnsServersHostsFile ensures that a name listed in the
// hosts file, such as a Pod hostAlias, resolves without asking the configured
// DNS servers.
func TestReachabilityCustomDnsServersHostsFile(t *testing.T) {
	u := startChallengeServer(t)

	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 "+challengeHost+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := hostsFile
	hostsFile = path
	t.Cleanup(func() { hostsFile = original })

	server := startDNSServer(t, replyRcode(dns.RcodeNameError), false)
	if err := testReachability(t.Context(), u, challengeKey, []string{server}, "cert-manager-test"); err != nil {
		t.Errorf("expected the self check to use the hosts file entry, but got: %v", err)
	}
}

func TestLookupHostsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	content := `# comment line
127.0.0.1	localhost
10.0.0.1 proxy.example.com proxy # trailing comment
10.0.0.2 Mixed.Example.com
fd00::1 proxy.example.com
not-an-ip proxy.example.com
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host string
		want []string
	}{
		{host: "proxy.example.com", want: []string{"10.0.0.1", "fd00::1"}},
		{host: "proxy", want: []string{"10.0.0.1"}},
		{host: "mixed.example.com.", want: []string{"10.0.0.2"}},
		{host: "comment", want: nil},
		{host: "missing.example.com", want: nil},
	}
	for _, tt := range tests {
		if got := lookupHostsFile(path, tt.host); !slices.Equal(got, tt.want) {
			t.Errorf("lookupHostsFile(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
	if got := lookupHostsFile(filepath.Join(t.TempDir(), "missing"), "localhost"); got != nil {
		t.Errorf("expected nil for a missing hosts file, got %v", got)
	}
}

// TestReachabilityCustomDnsServersIPAddress ensures that a challenge for an IP
// address is not sent to the configured DNS servers. There is nothing to
// resolve, so an unresponsive server must not prevent the check from running.
func TestReachabilityCustomDnsServersIPAddress(t *testing.T) {
	u := startChallengeServer(t)
	u.Host = net.JoinHostPort("127.0.0.1", u.Port())

	// 127.0.0.1:1 is not listening, so any attempt to use it as a resolver fails.
	if err := testReachability(t.Context(), u, challengeKey, []string{"127.0.0.1:1"}, "cert-manager-test"); err != nil {
		t.Errorf("expected an IP address challenge to skip DNS resolution, but got: %v", err)
	}
}
