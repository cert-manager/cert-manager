/*
Copyright 2026 The cert-manager Authors.

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

package testing

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/webhook/server"
)

// TestStartWebhookServerRetriesWhenItsPortIsTaken checks that StartWebhookServer
// hands back a server which is listening, even when the port the server picked
// has been claimed by something else in the meantime. See startAttempts for how
// that comes about.
func TestStartWebhookServerRetriesWhenItsPortIsTaken(t *testing.T) {
	takenPort := squatOnAPort(t)

	var attempts int
	serverOpts, stop := StartWebhookServer(
		t,
		// The webhook server builds a Kubernetes client at startup but never
		// calls the API server, so an address nothing is serving will do. It
		// only has to be set: with neither this nor --kubeconfig the server
		// falls back to in-cluster configuration and fails.
		[]string{"--api-server-host=https://127.0.0.1:1"},
		func(s *server.Server) {
			attempts++
			if attempts == 1 {
				s.ListenAddr = takenPort
			}
		},
	)
	t.Cleanup(stop)

	if attempts < 2 {
		t.Errorf("expected the webhook server to be started again after failing to bind, but it was started %d time(s)", attempts)
	}
	if serverOpts.URL == fmt.Sprintf("https://127.0.0.1:%d", takenPort) {
		t.Errorf("expected the webhook server to move off the port it could not bind (%d)", takenPort)
	}

	// The server it did settle on must really be ours and really be up.
	parsed, err := url.Parse(serverOpts.URL)
	if err != nil {
		t.Fatalf("failed parsing webhook server URL %q: %v", serverOpts.URL, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(serverOpts.CAPEM) {
		t.Fatal("failed parsing the CA returned for the webhook server")
	}
	dialCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	dialer := &tls.Dialer{Config: &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}}
	conn, err := dialer.DialContext(dialCtx, "tcp", parsed.Host)
	if err != nil {
		t.Fatalf("webhook server at %s is not accepting connections: %v", serverOpts.URL, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

// squatOnAPort holds a port open for the duration of the test and returns it,
// standing in for a concurrently starting webhook server that was allocated the
// same port. It answers connections rather than leaving them in the backlog, so
// that a caller probing the port sees a failed TLS handshake instead of waiting
// out its timeout.
//
// Holding the port on loopback alone is enough to deny it to the webhook server,
// which binds every interface.
func squatOnAPort(t *testing.T) int {
	t.Helper()

	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return // The listener has been closed.
			}
			_ = conn.Close()
		}
	}()

	return l.Addr().(*net.TCPAddr).Port
}
