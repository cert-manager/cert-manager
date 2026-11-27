/*
Copyright 2024 The cert-manager Authors.

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

package dns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/acmedns"
)

type tlsCerts struct {
	caPEM         []byte
	serverCertPEM []byte
	serverKeyPEM  []byte
}

func mustGenerateTLSCerts(t *testing.T) tlsCerts {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Integration Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})

	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatalf("failed to marshal server key: %v", err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	return tlsCerts{
		caPEM:         caPEM,
		serverCertPEM: serverCertPEM,
		serverKeyPEM:  serverKeyPEM,
	}
}

func mustStartHTTPSServer(t *testing.T, certs tlsCerts) *httptest.Server {
	t.Helper()

	serverCert, err := tls.X509KeyPair(certs.serverCertPEM, certs.serverKeyPEM)
	if err != nil {
		t.Fatalf("failed to create TLS key pair: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv
}

func TestAcmeDNSProviderEndToEndWithCustomCA(t *testing.T) {
	certs := mustGenerateTLSCerts(t)
	srv := mustStartHTTPSServer(t, certs)

	httpClient, err := buildHTTPClientFromCABundle(certs.caPEM)
	if err != nil {
		t.Fatalf("buildHTTPClientFromCABundle: %v", err)
	}
	if httpClient == nil {
		t.Fatal("expected non-nil http.Client")
	}

	accountJSON := []byte(`{
		"example.com": {
			"fulldomain": "test.auth.example.com",
			"subdomain": "test",
			"username": "testuser",
			"password": "testpass"
		}
	}`)

	t.Run("acmeDNS provider with custom CA httpClient — TLS to private-CA server succeeds", func(t *testing.T) {
		provider, err := acmedns.NewDNSProviderFromOptions(t.Context(),
			acmedns.Host(srv.URL),
			acmedns.AccountJSON(accountJSON),
			acmedns.HTTPClient{Client: httpClient})
		if err != nil {
			t.Fatalf("NewDNSProviderFromOptions: %v", err)
		}

		err = provider.Present(t.Context(), "example.com", "example.com.", "LG3tptA6W7T1vw4ujbmDxH2lLu6r8TUIqLZD3pzPmgE")
		if err != nil {
			t.Fatalf("Present with custom CA httpClient failed: %v", err)
		}
	})

	t.Run("acmeDNS provider without custom CA httpClient — TLS to private-CA server fails", func(t *testing.T) {
		provider, err := acmedns.NewDNSProviderFromOptions(t.Context(),
			acmedns.Host(srv.URL),
			acmedns.AccountJSON(accountJSON))
		if err != nil {
			t.Fatalf("NewDNSProviderFromOptions: %v", err)
		}

		err = provider.Present(t.Context(), "example.com", "example.com.", "LG3tptA6W7T1vw4ujbmDxH2lLu6r8TUIqLZD3pzPmgE")
		if err == nil {
			t.Fatal("expected TLS error when using default system trust against private CA, got nil")
		}
	})

	t.Run("acmeDNS provider with wrong CA httpClient — TLS to private-CA server fails", func(t *testing.T) {
		wrongCerts := mustGenerateTLSCerts(t)
		wrongClient, err := buildHTTPClientFromCABundle(wrongCerts.caPEM)
		if err != nil {
			t.Fatalf("buildHTTPClientFromCABundle(wrongCA): %v", err)
		}

		provider, err := acmedns.NewDNSProviderFromOptions(t.Context(),
			acmedns.Host(srv.URL),
			acmedns.AccountJSON(accountJSON),
			acmedns.HTTPClient{Client: wrongClient})
		if err != nil {
			t.Fatalf("NewDNSProviderFromOptions: %v", err)
		}

		err = provider.Present(t.Context(), "example.com", "example.com.", "LG3tptA6W7T1vw4ujbmDxH2lLu6r8TUIqLZD3pzPmgE")
		if err == nil {
			t.Fatal("expected TLS error when using wrong CA, got nil")
		}
	})
}
