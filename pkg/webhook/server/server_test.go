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

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

type contextKey struct{}

func TestWithShutdownDelay(t *testing.T) {
	t.Run("cancels the delay after the parent is done", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const delay = 5 * time.Second
			cause := errors.New("received signal 15")

			parent, cancelParent := context.WithCancelCause(context.WithValue(t.Context(), contextKey{}, "value"))
			var onDelayCalls int
			ctx, stop := withShutdownDelay(parent, delay, func() { onDelayCalls++ })
			defer stop()

			if got := ctx.Value(contextKey{}); got != "value" {
				t.Errorf("expected the context to keep the parent's values, got %v", got)
			}

			cancelParent(cause)
			synctest.Wait()
			if onDelayCalls != 1 {
				t.Errorf("expected onDelay to be called once the parent is done, got %d calls", onDelayCalls)
			}

			time.Sleep(delay - time.Nanosecond)
			synctest.Wait()
			if err := ctx.Err(); err != nil {
				t.Fatalf("expected the context to stay open until the delay has passed, got %v", err)
			}

			time.Sleep(time.Nanosecond)
			synctest.Wait()
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("expected the context to be cancelled once the delay has passed, got %v", ctx.Err())
			}
			if got := context.Cause(ctx); got != cause {
				t.Errorf("expected the context to have the parent's cause %q, got %q", cause, got)
			}
			if onDelayCalls != 1 {
				t.Errorf("expected onDelay to be called once, got %d calls", onDelayCalls)
			}
		})
	})

	t.Run("without a delay cancels together with the parent", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			parent, cancelParent := context.WithCancel(t.Context())
			ctx, stop := withShutdownDelay(parent, 0, func() { t.Error("onDelay must not be called without a delay") })
			defer stop()

			cancelParent()
			synctest.Wait()
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("expected the context to be cancelled with its parent, got %v", ctx.Err())
			}
		})
	})

	t.Run("stop before the parent is done", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, stop := withShutdownDelay(t.Context(), time.Hour, func() { t.Error("onDelay must not be called when the parent is not done") })

			stop()
			synctest.Wait()
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("expected stop to cancel the context, got %v", ctx.Err())
			}
			// synctest.Test fails if the goroutine waiting on the parent is
			// still blocked when this returns.
		})
	})

	t.Run("stop during the delay", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			parent, cancelParent := context.WithCancel(t.Context())
			ctx, stop := withShutdownDelay(parent, time.Hour, func() {})

			cancelParent()
			synctest.Wait()
			if err := ctx.Err(); err != nil {
				t.Fatalf("expected the context to stay open during the delay, got %v", err)
			}

			stop()
			synctest.Wait()
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("expected stop to cancel the context, got %v", ctx.Err())
			}
			// synctest.Test fails if the goroutine waiting on the timer is
			// still blocked when this returns.
		})
	})
}

// TestRunKeepsServingDuringShutdownDelay checks that the webhook listener
// still accepts connections after the context passed to Run is cancelled,
// and that Run does not return until ShutdownDelay has passed. The exact
// timing is covered by TestWithShutdownDelay, so the delay here only has to
// be long enough for a TLS handshake on a busy machine.
func TestRunKeepsServingDuringShutdownDelay(t *testing.T) {
	const delay = 5 * time.Second

	certificateSource, roots := newTestCertificateSource(t)
	run := startServer(t, roots, func() *Server {
		return &Server{
			CertificateSource:    certificateSource,
			MetricsListenAddress: "0",
			ShutdownDelay:        delay,
		}
	})

	cancelledAt := time.Now()
	run.cancel()

	handshakeCtx, cancelHandshake := context.WithDeadline(t.Context(), cancelledAt.Add(delay))
	defer cancelHandshake()
	if err := tlsHandshake(handshakeCtx, run.addr, roots); err != nil {
		t.Fatalf("expected the webhook server to accept connections during the shutdown delay, got %v", err)
	}

	select {
	case result := <-run.result:
		if result.err != nil {
			t.Fatalf("unexpected error from Run: %v", result.err)
		}
		if elapsed := result.returnedAt.Sub(cancelledAt); elapsed < delay {
			t.Errorf("expected Run to return no earlier than the shutdown delay of %s, but it returned after %s", delay, elapsed)
		}
	case <-time.After(delay + 30*time.Second):
		t.Fatal("Run did not return after the shutdown delay")
	}
}

// serverStartAttempts is how many times startServer tries to start a server.
// With ListenAddr 0, Run picks a free port and then binds it, so another
// process can take the port in between. test/webhook retries for the same
// reason.
const serverStartAttempts = 5

type runResult struct {
	err        error
	returnedAt time.Time
}

type runningServer struct {
	addr   string
	cancel context.CancelFunc
	result <-chan runResult
}

// startServer runs a server built by newServer and returns once its webhook
// listener completes a TLS handshake. It builds and runs a new server if the
// port Run chose was taken before Run could bind it.
func startServer(t *testing.T, roots *x509.CertPool, newServer func() *Server) runningServer {
	t.Helper()

	for attempt := 1; ; attempt++ {
		srv := newServer()

		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan runResult, 1)
		go func() {
			err := srv.Run(ctx)
			result <- runResult{err: err, returnedAt: time.Now()}
		}()

		addr, err := waitUntilServing(t.Context(), srv, roots, result)
		if err == nil {
			t.Cleanup(cancel)
			return runningServer{addr: addr, cancel: cancel, result: result}
		}
		cancel()

		if attempt >= serverStartAttempts || !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("failed to start the webhook server: %v", err)
		}
		t.Logf("webhook server lost the race for its port, retrying (attempt %d of %d): %v", attempt, serverStartAttempts, err)
	}
}

// waitUntilServing returns the address of the webhook listener once it
// completes a TLS handshake, or the error Run returned if it stops first.
func waitUntilServing(ctx context.Context, srv *Server, roots *x509.CertPool, result <-chan runResult) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	stopped := func(r runResult) error {
		return fmt.Errorf("the webhook server stopped before it was serving: %w", r.err)
	}

	var lastErr error
	for {
		if port, err := srv.Port(); err != nil {
			lastErr = err
		} else {
			// Bound each probe, so that something else holding the port
			// which accepts connections but never answers cannot use up the
			// whole wait and hide the error Run returned.
			addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
			probeCtx, cancelProbe := context.WithTimeout(ctx, time.Second)
			lastErr = tlsHandshake(probeCtx, addr, roots)
			cancelProbe()
			if lastErr == nil {
				return addr, nil
			}
		}

		select {
		case r := <-result:
			return "", stopped(r)
		case <-ctx.Done():
			// Report why Run stopped, if it did, rather than the timeout.
			select {
			case r := <-result:
				return "", stopped(r)
			default:
			}
			return "", fmt.Errorf("webhook server was not serving in time, last error: %w", lastErr)
		case <-ticker.C:
		}
	}
}

// TestStartServerRetriesWhenItsPortIsTaken checks that startServer starts a
// new server when Run cannot bind the port it chose, even when whatever holds
// that port accepts connections and never answers them.
func TestStartServerRetriesWhenItsPortIsTaken(t *testing.T) {
	takenPort, probes := holdPortWithoutAnswering(t)

	certificateSource, roots := newTestCertificateSource(t)
	var attempts int
	run := startServer(t, roots, func() *Server {
		attempts++
		srv := &Server{
			CertificateSource:    certificateSource,
			MetricsListenAddress: "0",
		}
		if attempts == 1 {
			srv.ListenAddr = takenPort
			// Report the port straight away, as Run would, so that the
			// first probe is sure to reach the listener that never answers.
			srv.listenPort.Store(int64(takenPort))
		}
		return srv
	})

	if attempts < 2 {
		t.Errorf("expected a new server to be started after the first failed to bind, but %d were started", attempts)
	}
	if run.addr == net.JoinHostPort("127.0.0.1", fmt.Sprint(takenPort)) {
		t.Errorf("expected the server to move off the port it could not bind (%d)", takenPort)
	}
	if probes.Load() == 0 {
		t.Error("expected startServer to probe the port that was taken")
	}
}

// holdPortWithoutAnswering listens on a port for the rest of the test and
// returns it, along with a count of the connections it has accepted. It
// leaves the connections open without writing to them, so a TLS handshake
// against it waits until the client gives up.
func holdPortWithoutAnswering(t *testing.T) (int, *atomic.Int32) {
	t.Helper()

	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var conns []net.Conn
	var count atomic.Int32
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := l.Accept()
			if err != nil {
				return // The listener has been closed.
			}
			conns = append(conns, conn)
			count.Add(1)
		}
	}()
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
		<-accepted
		for _, conn := range conns {
			_ = conn.Close()
		}
	})

	return l.Addr().(*net.TCPAddr).Port, &count
}

func tlsHandshake(ctx context.Context, addr string, roots *x509.CertPool) error {
	dialer := &tls.Dialer{Config: &tls.Config{
		RootCAs:    roots,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// testCertificateSource serves a fixed self-signed certificate.
type testCertificateSource struct {
	certificate *tls.Certificate
}

func (s *testCertificateSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.certificate, nil
}

func (s *testCertificateSource) Start(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (s *testCertificateSource) Healthy() bool {
	return true
}

// newTestCertificateSource returns a certificate source for 127.0.0.1 and a
// pool which trusts it.
func newTestCertificateSource(t *testing.T) (*testCertificateSource, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cert-manager-webhook-test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	return &testCertificateSource{
		certificate: &tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  key,
			Leaf:        cert,
		},
	}, roots
}
