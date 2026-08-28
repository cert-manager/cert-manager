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

package testing

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cert-manager/cert-manager/internal/webhook"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/pkg/webhook/options"
	"github.com/cert-manager/cert-manager/pkg/webhook/server"
)

// NOTE: all functions that return a StopFunc should use
// context.WithCancel(t.Context()) instead of just t.Context()
type StopFunc func()

type ServerOptions struct {
	// URL is the base path/URL that the webhook server can be accessed on.
	// This is typically of the form: https://127.0.0.1:12345.
	URL string

	// CAPEM is PEM data containing the CA used to validate connections to the
	// webhook.
	// If `--tls-cert-file` or `--tls-private-key-file` are explicitly provided
	// as flags, this field will be empty.
	CAPEM []byte
}

// startAttempts is the number of times StartWebhookServer tries to bring up a
// webhook server before giving up.
//
// The server chooses its port by binding to port 0, closing that listener and
// then binding again to the port number it was allocated. Anything else on the
// machine can take the port in between; `go test ./...` runs the integration
// test packages concurrently and each starts its own webhook server, so they
// race each other. The loser exits with "address already in use", and a fresh
// attempt is allocated a different port.
const startAttempts = 5

func StartWebhookServer(t *testing.T, args []string, argumentsForNewServerWithOptions ...func(*server.Server)) (ServerOptions, StopFunc) {
	t.Helper()

	for attempt := 1; ; attempt++ {
		serverOpts, stop, err := startWebhookServer(t, args, argumentsForNewServerWithOptions...)
		if err == nil {
			return serverOpts, stop
		}
		if attempt >= startAttempts || !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("failed to start webhook server: %v", err)
		}
		t.Logf("webhook server lost the race for its port, retrying (attempt %d of %d): %v", attempt, startAttempts, err)
	}
}

func startWebhookServer(t *testing.T, args []string, argumentsForNewServerWithOptions ...func(*server.Server)) (ServerOptions, StopFunc, error) {
	t.Helper()

	// We have to use a global stdout logger, because otherwise -count=2 tests will
	// fail with "panic: Log in goroutine after Test... has completed: ..." since the
	// first call to ctrl.SetLogger() will set the logger to the logger linked to the
	// first test, controller-runtime will ignore the second call to ctrl.SetLogger()
	// and the second test will end up using the logger linked to the first test, which
	// will cause the panic.
	globalLogger := klog.Background()
	ctrl.SetLogger(globalLogger)

	// Making sure the rootCtx is canceled when StopFunc is called
	// even when t.Context() has not been canceled yet.
	stoppableCtx, stopCtxFn := context.WithCancel(t.Context())

	log := testr.New(t)
	stoppableCtx = logr.NewContext(stoppableCtx, log)

	fs := pflag.NewFlagSet("testset", pflag.ExitOnError)
	webhookFlags := options.NewWebhookFlags()
	webhookConfig, err := options.NewWebhookConfiguration()
	if err != nil {
		t.Fatalf("Failed building test webhook config: %v", err)
	}
	webhookFlags.AddFlags(fs)
	options.AddConfigFlags(fs, webhookConfig)
	// Parse the arguments passed in into the WebhookOptions struct
	if err := fs.Parse(args); err != nil {
		t.Fatalf("Failed parsing arguments: %v", err)
	}

	var caPEM []byte
	tempDir := t.TempDir()
	if !webhookConfig.TLSConfig.FilesystemConfigProvided() && !webhookConfig.TLSConfig.DynamicConfigProvided() {
		// Generate a CA and serving certificate
		ca, certificatePEM, privateKeyPEM, err := generateTLSAssets()
		if err != nil {
			t.Fatalf("failed to generate PKI assets: %v", err)
		}

		caPEM = ca
		if err := os.WriteFile(filepath.Join(tempDir, "tls.crt"), certificatePEM, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tempDir, "tls.key"), privateKeyPEM, 0644); err != nil {
			t.Fatal(err)
		}

		webhookConfig.TLSConfig.Filesystem.KeyFile = filepath.Join(tempDir, "tls.key")
		webhookConfig.TLSConfig.Filesystem.CertFile = filepath.Join(tempDir, "tls.crt")
	}

	// Listen on a random port number
	webhookConfig.SecurePort = 0
	webhookConfig.HealthzPort = 0
	// Disable the metrics server, preventing "failed to start metrics server: failed
	// to create listener: listen tcp 0.0.0.0:9402: bind: address already in use" issues
	// when running multiple tests
	webhookConfig.MetricsListenAddress = "0"

	errCh := make(chan error)
	srv, err := webhook.NewCertManagerWebhookServer(log, *webhookConfig, argumentsForNewServerWithOptions...)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		defer close(errCh)
		if err := srv.Run(stoppableCtx); err != nil {
			errCh <- fmt.Errorf("error running webhook server: %w", err)
		}
	}()

	// stop asks the server to shut down and waits for Run to return.
	stop := func() error {
		stopCtxFn()
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}

	listenPort, err := waitForListener(stoppableCtx, srv, errCh, caPEM)
	if err != nil {
		_ = stop() // Whatever went wrong is already in err.
		return ServerOptions{}, nil, err
	}

	serverOpts := ServerOptions{
		URL:   fmt.Sprintf("https://127.0.0.1:%d", listenPort),
		CAPEM: caPEM,
	}
	return serverOpts, func() {
		if err := stop(); err != nil {
			t.Fatal(err)
		}
	}, nil
}

// waitForListener returns the port the webhook server is listening on, once it
// is accepting connections. It returns an error if the server stops first. It
// is modelled on controller-runtime's DefaultServer.StartedChecker, which is not
// reachable from here because Server.Run does not keep the manager it builds.
//
// caPEM is the CA that issued the server's serving certificate, or empty if the
// caller supplied its own TLS files.
func waitForListener(ctx context.Context, srv *server.Server, errCh <-chan error, caPEM []byte) (int, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		// Check the server's certificate against the CA that was generated for
		// it, so that another process holding the port cannot be mistaken for
		// our server.
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return 0, errors.New("failed parsing the CA generated for the webhook server")
		}
		tlsConfig.RootCAs = roots
	} else {
		// The caller supplied its own TLS files, so there is no CA to check
		// against and reaching the port has to be good enough.
		tlsConfig.InsecureSkipVerify = true
	}

	dialer := &tls.Dialer{Config: tlsConfig}

	var listenPort int

	err := wait.PollUntilContextCancel(ctx, 10*time.Millisecond, true, func(_ context.Context) (bool, error) {
		select {
		case err, ok := <-errCh:
			if !ok {
				return false, errors.New("webhook server stopped before it began listening")
			}
			return false, err
		default:
		}

		port, err := srv.Port()
		if err != nil {
			if errors.Is(err, server.ErrNotListening) {
				return false, nil
			}
			return false, err
		}

		// Port reports the port number as soon as it has been chosen, which is
		// before the listener has been created, so connect to it to confirm that
		// the server really is up. Without this the caller can be handed the
		// details of a server that failed to bind, and every request to it is
		// then refused. The deadline covers the TLS handshake as well as the
		// connection, so that a listener which never replies cannot wedge the
		// poll; a loopback handshake takes single-digit milliseconds.
		dialCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		cancel()
		if err != nil {
			return false, nil //nolint:nilerr // not listening yet, keep polling
		}
		if err := conn.Close(); err != nil {
			return false, err
		}

		listenPort = port
		return true, nil
	})

	return listenPort, err
}

func generateTLSAssets() (caPEM, certificatePEM, privateKeyPEM []byte, err error) {
	caPK, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCA := &x509.Certificate{
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1658),
		PublicKeyAlgorithm:    x509.RSA,
		Subject: pkix.Name{
			CommonName: "testing-ca",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IsCA:      true,
	}
	rootCADER, err := x509.CreateCertificate(rand.Reader, rootCA, rootCA, caPK.Public(), caPK)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCA, err = x509.ParseCertificate(rootCADER)
	if err != nil {
		return nil, nil, nil, err
	}
	servingCert := &x509.Certificate{
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1659),
		PublicKeyAlgorithm:    x509.RSA,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{{127, 0, 0, 1}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	servingPK, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	servingDER, err := x509.CreateCertificate(rand.Reader, servingCert, rootCA, servingPK.Public(), caPK)
	if err != nil {
		return nil, nil, nil, err
	}
	servingCert, err = x509.ParseCertificate(servingDER)
	if err != nil {
		return nil, nil, nil, err
	}

	// encoding PKI data to PEM
	privateKeyPEM, err = pki.EncodePKCS8PrivateKey(servingPK)
	if err != nil {
		return nil, nil, nil, err
	}
	caPEM, err = pki.EncodeX509(rootCA)
	if err != nil {
		return nil, nil, nil, err
	}
	certificatePEM, err = pki.EncodeX509(servingCert)
	if err != nil {
		return nil, nil, nil, err
	}
	return caPEM, certificatePEM, privateKeyPEM, nil
}
