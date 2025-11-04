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
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
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
		reachabilityTest func(context.Context, *url.URL, string, []string, string) error
		challenge        *cmacme.Challenge
		expectedErr      bool
		expectedStatus   cmmeta.ConditionStatus
		expectedReason   string
		expectedSuccess  int64
	}
	tests := []testT{
		{
			name: "should pass after reaching threshold",
			challenge: &cmacme.Challenge{
				Status: cmacme.ChallengeStatus{
					Solver: cmacme.ChallengeSolverStatus{
						HTTP: &cmacme.ChallengeSolverStatusHTTP{
							RequiredSuccesses: 5,
							Successes:         4,
						},
					},
				},
			},
			reachabilityTest: func(context.Context, *url.URL, string, []string, string) error {
				return nil
			},
			expectedErr:     false,
			expectedStatus:  cmmeta.ConditionTrue,
			expectedReason:  "ChallengeSelfCheckPassed",
			expectedSuccess: 5,
		},
		{
			name: "should error and reset success count",
			challenge: &cmacme.Challenge{
				Status: cmacme.ChallengeStatus{
					Solver: cmacme.ChallengeSolverStatus{
						HTTP: &cmacme.ChallengeSolverStatusHTTP{
							RequiredSuccesses: 5,
							Successes:         4,
						},
					},
				},
			},
			reachabilityTest: func(context.Context, *url.URL, string, []string, string) error {
				return fmt.Errorf("failed")
			},
			expectedErr:     false, // still nil because Check returns nil for expected check failures
			expectedStatus:  cmmeta.ConditionFalse,
			expectedReason:  "ChallengeSelfCheckFailed",
			expectedSuccess: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			requiredCallsForPass := int64(5)

			s := Solver{
				Context:          &controller.Context{RESTConfig: &rest.Config{UserAgent: "test-agent"}},
				testReachability: countReachabilityTestCalls(&calls, test.reachabilityTest),
				requiredPasses:   int(requiredCallsForPass),
			}

			result, status, err := s.Check(t.Context(), nil, test.challenge)

			if (err != nil) != test.expectedErr {
				t.Errorf("expected error: %v, got: %v", test.expectedErr, err)
			}

			if result.Status != test.expectedStatus {
				t.Errorf("expected status %q, got %q", test.expectedStatus, result.Status)
			}

			if result.Reason != test.expectedReason {
				t.Errorf("expected reason %q, got %q", test.expectedReason, result.Reason)
			}

			if got := status.HTTP.Successes; got != test.expectedSuccess {
				t.Errorf("expected HTTP.Successes=%d, got %d", test.expectedSuccess, got)
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
	ips, err := net.LookupIP(u.Host) // nolint: noctx // We intentionally use LookupIP here for test compatibility
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
