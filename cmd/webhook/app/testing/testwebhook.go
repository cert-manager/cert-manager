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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/cert-manager/cert-manager/cmd/webhook/app"
	"github.com/cert-manager/cert-manager/cmd/webhook/app/options"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

var log = logf.Log.WithName("webhook-server-test")

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

func StartWebhookServer(t *testing.T, args []string) (ServerOptions, StopFunc) {
	// Allow user to override options using flags
	var opts options.WebhookOptions
	fs := pflag.NewFlagSet("testset", pflag.ExitOnError)
	opts.AddFlags(fs)
	// Parse the arguments passed in into the WebhookOptions struct
	fs.Parse(args)

	var caPEM []byte
	tempDir, err := ioutil.TempDir("", "webhook-tls-")
	if err != nil {
		t.Fatal(err)
	}
	if !options.FileTLSSourceEnabled(opts) && !options.DynamicTLSSourceEnabled(opts) {
		// Generate a CA and serving certificate
		ca, certificatePEM, privateKeyPEM, err := generateTLSAssets()
		if err != nil {
			t.Fatalf("failed to generate PKI assets: %v", err)
		}

		caPEM = ca
		if err := ioutil.WriteFile(filepath.Join(tempDir, "tls.crt"), certificatePEM, 0644); err != nil {
			t.Fatal(err)
		}
		if err := ioutil.WriteFile(filepath.Join(tempDir, "tls.key"), privateKeyPEM, 0644); err != nil {
			t.Fatal(err)
		}

		opts.TLSKeyFile = filepath.Join(tempDir, "tls.key")
		opts.TLSCertFile = filepath.Join(tempDir, "tls.crt")
	}

	// Listen on a random port number
	opts.ListenPort = 0
	opts.HealthzPort = 0

	stopCh := make(chan struct{})
	srv, err := app.NewServerWithOptions(log, opts)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := srv.Run(stopCh); err != nil {
			t.Fatalf("error running webhook server: %v", err)
		}
	}()

	// Determine the random port number that was chosen
	var listenPort int
	for i := 0; i < 10; i++ {
		listenPort, err = srv.Port()
		if err != nil {
			t.Logf("Waiting for ListenPort to be allocated (got error: %v)", err)
			time.Sleep(time.Second)
			continue
		}
		break
	}

	serverOpts := ServerOptions{
		URL:   fmt.Sprintf("https://127.0.0.1:%d", listenPort),
		CAPEM: caPEM,
	}
	return serverOpts, func() {
		close(stopCh)
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
