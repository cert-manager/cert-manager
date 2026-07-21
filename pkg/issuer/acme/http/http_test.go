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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

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
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
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
				atomic.StoreInt32(&dnsServerCalled, 1)
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
				atomic.StoreInt32(&dnsServerCalled, 1)
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
	})

	go func() {
		if err := server.ListenAndServe(); err != nil {
			t.Error(err)
		}
	}()

	// Wait for server to have started
	<-dnsServerStarted

	key := "there is no key"

	tests := []struct {
		name            string
		dnsServers      []string
		dnsServerCalled bool
	}{
		{
			name:            "custom dns servers",
			dnsServers:      []string{"127.0.0.1:15353"},
			dnsServerCalled: true,
		},
		{
			name:            "system dns servers",
			dnsServerCalled: false,
		},
	}

	for _, tt := range tests {
		atomic.StoreInt32(&dnsServerCalled, 0)
		err = testReachability(t.Context(), u, key, tt.dnsServers, "cert-manager-test")
		switch {
		case err == nil:
			t.Errorf("Expected error for testReachability, but got none")
		case strings.Contains(err.Error(), key):
			called := atomic.LoadInt32(&dnsServerCalled) == 1
			if called != tt.dnsServerCalled {
				t.Errorf("Expected DNS server called: %v, but got %v", tt.dnsServerCalled, called)
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
