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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	logtesting "github.com/go-logr/logr/testing"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/cert-manager/internal/webhook"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/pkg/webhook/options"
	"github.com/cert-manager/cert-manager/pkg/webhook/server"
)

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

func StartWebhookServer(t *testing.T, ctx context.Context, args []string, argumentsForNewServerWithOptions ...func(*server.Server)) (ServerOptions, StopFunc) {
	log := logtesting.NewTestLogger(t)

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
	tempDir, err := os.MkdirTemp("", "webhook-tls-")
	if err != nil {
		t.Fatal(err)
	}
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

	errCh := make(chan error)
	srv, err := webhook.NewCertManagerWebhookServer(log, *webhookConfig, argumentsForNewServerWithOptions...)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	go func() {
		defer close(errCh)
		if err := srv.Run(ctx); err != nil {
			errCh <- fmt.Errorf("error running webhook server: %v", err)
		}
	}()

	// Determine the random port number that was chosen
	var listenPort int
	if err := wait.PollUntilContextCancel(ctx, 100*time.Millisecond, true, func(_ context.Context) (bool, error) {
		listenPort, err = srv.Port()
		if err != nil {
			if errors.Is(err, server.ErrNotListening) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}); err != nil {
		t.Fatalf("Failed waiting for ListenPort to be allocated (got error: %v)", err)
	}

	serverOpts := ServerOptions{
		URL:   fmt.Sprintf("https://127.0.0.1:%d", listenPort),
		CAPEM: caPEM,
	}
	return serverOpts, func() {
		cancel()
		err := <-errCh // Wait for shutdown
		if err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(tempDir); err != nil {
			t.Fatal(err)
		}
	}
}

func generateTLSAssets() (caPEM, certificatePEM, privateKeyPEM []byte, err error) {
	caPK, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCA := &x509.Certificate{
		Version:               3,
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
		Version:               3,
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
	return
}
