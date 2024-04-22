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

			err := s.Check(context.Background(), nil, test.challenge)
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
	ips, err := net.LookupIP(u.Host)
	if err != nil {
		t.Fatalf("Failed to resolve %s: %v", u.Host, err)
	}

	dnsServerStarted := make(chan struct{})
	dnsServerCalled := int32(0)

	server := &dns.Server{Addr: "127.0.0.1:15353", Net: "udp", NotifyStartedFunc: func() { close(dnsServerStarted) }}
	defer server.Shutdown()

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
		err = testReachability(context.Background(), u, key, tt.dnsServers, "cert-manager-test")
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
