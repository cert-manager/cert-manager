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
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	goruntime "k8s.io/apimachinery/pkg/runtime"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/acmedns"
	"github.com/cert-manager/cert-manager/test/unit/gen"
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

func buildSolverWithCertManagerObjects(t *testing.T, cmObjs ...goruntime.Object) *Solver {
	t.Helper()
	b := &test.Builder{
		CertManagerObjects: cmObjs,
	}
	b.T = t
	b.InitWithRESTConfig()
	s := &Solver{
		Context:             b.Context,
		secretLister:        b.Context.KubeSharedInformerFactory.Secrets().Lister(),
		issuerLister:        b.Context.SharedInformerFactory.Certmanager().V1().Issuers().Lister(),
		clusterIssuerLister: b.Context.SharedInformerFactory.Certmanager().V1().ClusterIssuers().Lister(),
	}
	b.Start()
	b.Sync()
	t.Cleanup(func() { b.Stop() })
	return s
}

func TestCaBundleIntegration(t *testing.T) {
	certsA := mustGenerateTLSCerts(t)
	certsB := mustGenerateTLSCerts(t)

	srvA := mustStartHTTPSServer(t, certsA)

	const (
		issuerName = "test-issuer"
		ns         = "test-ns"
	)

	tests := map[string]struct {
		buildClient  func(t *testing.T) *http.Client
		expectGetErr bool
		errSubstr    string
	}{
		"per-solver caBundle — TLS to custom-CA HTTPS server succeeds": {
			buildClient: func(t *testing.T) *http.Client {
				t.Helper()
				client, err := buildHTTPClientFromCABundle(certsA.caPEM)
				if err != nil {
					t.Fatalf("buildHTTPClientFromCABundle: %v", err)
				}
				if client == nil {
					t.Fatal("expected non-nil *http.Client")
				}
				return client
			},
			expectGetErr: false,
		},
		"no caBundle — system trust store — TLS to custom-CA HTTPS server fails with x509 error": {
			buildClient: func(t *testing.T) *http.Client {
				t.Helper()
				client, err := buildHTTPClientFromCABundle(nil)
				if err != nil {
					t.Fatalf("buildHTTPClientFromCABundle(nil): %v", err)
				}
				if client != nil {
					t.Fatal("expected nil *http.Client for nil caBundle")
				}
				return http.DefaultClient
			},
			expectGetErr: true,
			errSubstr:    "certificate",
		},
		"per-solver caBundle overrides issuer-level caBundle — wrong CA fails, correct CA succeeds": {
			buildClient: func(t *testing.T) *http.Client {
				t.Helper()
				clientA, err := buildHTTPClientFromCABundle(certsA.caPEM)
				if err != nil {
					t.Fatalf("buildHTTPClientFromCABundle(certsA): %v", err)
				}

				clientB, err := buildHTTPClientFromCABundle(certsB.caPEM)
				if err != nil {
					t.Fatalf("buildHTTPClientFromCABundle(certsB): %v", err)
				}

				_, wrongCAErr := clientB.Get(srvA.URL)
				if wrongCAErr == nil {
					t.Fatal("expected TLS error when using wrong CA (CA-B against CA-A signed server cert)")
				}
				if !strings.Contains(wrongCAErr.Error(), "certificate") &&
					!strings.Contains(wrongCAErr.Error(), "x509") &&
					!strings.Contains(wrongCAErr.Error(), "tls") {
					t.Fatalf("expected x509/certificate/tls error from wrong CA, got: %v", wrongCAErr)
				}

				return clientA
			},
			expectGetErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			client := tc.buildClient(t)
			resp, err := client.Get(srvA.URL)
			if tc.expectGetErr {
				if err == nil {
					t.Fatal("expected TLS error, got nil")
				}
				if tc.errSubstr != "" &&
					!strings.Contains(err.Error(), tc.errSubstr) &&
					!strings.Contains(err.Error(), "x509") &&
					!strings.Contains(err.Error(), "tls") {
					t.Fatalf("expected error containing %q, got: %v", tc.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected TLS error: %v", err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
				}
			}
		})
	}

	t.Run("issuer-level caBundle — resolveCABundle returns issuer CA — TLS succeeds", func(t *testing.T) {
		challenge := &cmacme.Challenge{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns},
			Spec: cmacme.ChallengeSpec{
				Solver: cmacme.ACMEChallengeSolver{
					DNS01: &cmacme.ACMEChallengeSolverDNS01{
						AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{},
					},
				},
				IssuerRef: cmmeta.IssuerReference{
					Name: issuerName,
				},
			},
		}

		solver := buildSolverWithCertManagerObjects(t,
			gen.Issuer(issuerName,
				gen.SetIssuerNamespace(ns),
				gen.SetIssuerACME(cmacme.ACMEIssuer{
					Server:   srvA.URL,
					CABundle: certsA.caPEM,
				}),
			),
		)

		caBundle, err := solver.resolveCABundle(challenge)
		if err != nil {
			t.Fatalf("resolveCABundle: unexpected error: %v", err)
		}

		client, err := buildHTTPClientFromCABundle(caBundle)
		if err != nil {
			t.Fatalf("buildHTTPClientFromCABundle: unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client from issuer-level caBundle")
		}

		resp, err := client.Get(srvA.URL)
		if err != nil {
			t.Fatalf("GET %s: unexpected TLS error: %v", srvA.URL, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
	})

	t.Run("per-solver caBundle overrides issuer-level via resolveCABundle — correct CA used — TLS succeeds", func(t *testing.T) {
		challenge := &cmacme.Challenge{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns},
			Spec: cmacme.ChallengeSpec{
				Solver: cmacme.ACMEChallengeSolver{
					DNS01: &cmacme.ACMEChallengeSolverDNS01{
						AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{
							CABundle: certsA.caPEM,
						},
					},
				},
				IssuerRef: cmmeta.IssuerReference{
					Name: issuerName,
				},
			},
		}

		solver := buildSolverWithCertManagerObjects(t,
			gen.Issuer(issuerName,
				gen.SetIssuerNamespace(ns),
				gen.SetIssuerACME(cmacme.ACMEIssuer{
					Server:   srvA.URL,
					CABundle: certsB.caPEM,
				}),
			),
		)

		caBundle, err := solver.resolveCABundle(challenge)
		if err != nil {
			t.Fatalf("resolveCABundle: unexpected error: %v", err)
		}

		if string(caBundle) != string(certsA.caPEM) {
			t.Fatalf("resolveCABundle returned issuer bundle instead of per-solver bundle")
		}

		client, err := buildHTTPClientFromCABundle(caBundle)
		if err != nil {
			t.Fatalf("buildHTTPClientFromCABundle: unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client")
		}

		resp, err := client.Get(srvA.URL)
		if err != nil {
			t.Fatalf("GET %s: unexpected TLS error with per-solver CA: %v", srvA.URL, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
	})

	t.Run("ClusterIssuer caBundle — resolveCABundle returns ClusterIssuer CA — TLS succeeds", func(t *testing.T) {
		const clusterIssuerName = "test-cluster-issuer"

		challenge := &cmacme.Challenge{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns},
			Spec: cmacme.ChallengeSpec{
				Solver: cmacme.ACMEChallengeSolver{
					DNS01: &cmacme.ACMEChallengeSolverDNS01{
						AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{},
					},
				},
				IssuerRef: cmmeta.IssuerReference{
					Name: clusterIssuerName,
					Kind: "ClusterIssuer",
				},
			},
		}

		solver := buildSolverWithCertManagerObjects(t,
			gen.ClusterIssuer(clusterIssuerName,
				gen.SetIssuerACME(cmacme.ACMEIssuer{
					Server:   srvA.URL,
					CABundle: certsA.caPEM,
				}),
			),
		)

		caBundle, err := solver.resolveCABundle(challenge)
		if err != nil {
			t.Fatalf("resolveCABundle: unexpected error: %v", err)
		}

		client, err := buildHTTPClientFromCABundle(caBundle)
		if err != nil {
			t.Fatalf("buildHTTPClientFromCABundle: unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client from ClusterIssuer caBundle")
		}

		resp, err := client.Get(srvA.URL)
		if err != nil {
			t.Fatalf("GET %s: unexpected TLS error: %v", srvA.URL, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
	})

	t.Run("per-solver caBundle overrides ClusterIssuer via resolveCABundle — correct CA used — TLS succeeds", func(t *testing.T) {
		const clusterIssuerName = "test-cluster-issuer-override"

		challenge := &cmacme.Challenge{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns},
			Spec: cmacme.ChallengeSpec{
				Solver: cmacme.ACMEChallengeSolver{
					DNS01: &cmacme.ACMEChallengeSolverDNS01{
						AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{
							CABundle: certsA.caPEM,
						},
					},
				},
				IssuerRef: cmmeta.IssuerReference{
					Name: clusterIssuerName,
					Kind: "ClusterIssuer",
				},
			},
		}

		solver := buildSolverWithCertManagerObjects(t,
			gen.ClusterIssuer(clusterIssuerName,
				gen.SetIssuerACME(cmacme.ACMEIssuer{
					Server:   srvA.URL,
					CABundle: certsB.caPEM,
				}),
			),
		)

		caBundle, err := solver.resolveCABundle(challenge)
		if err != nil {
			t.Fatalf("resolveCABundle: unexpected error: %v", err)
		}

		if string(caBundle) != string(certsA.caPEM) {
			t.Fatalf("resolveCABundle returned ClusterIssuer bundle instead of per-solver bundle")
		}

		client, err := buildHTTPClientFromCABundle(caBundle)
		if err != nil {
			t.Fatalf("buildHTTPClientFromCABundle: unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client")
		}

		resp, err := client.Get(srvA.URL)
		if err != nil {
			t.Fatalf("GET %s: unexpected TLS error with per-solver CA: %v", srvA.URL, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
	})
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
		provider, err := acmedns.NewDNSProviderHostBytes(srv.URL, accountJSON, nil, httpClient)
		if err != nil {
			t.Fatalf("NewDNSProviderHostBytes: %v", err)
		}

		err = provider.Present(t.Context(), "example.com", "example.com.", "LG3tptA6W7T1vw4ujbmDxH2lLu6r8TUIqLZD3pzPmgE")
		if err != nil {
			t.Fatalf("Present with custom CA httpClient failed: %v", err)
		}
	})

	t.Run("acmeDNS provider without custom CA httpClient — TLS to private-CA server fails", func(t *testing.T) {
		provider, err := acmedns.NewDNSProviderHostBytes(srv.URL, accountJSON, nil, nil)
		if err != nil {
			t.Fatalf("NewDNSProviderHostBytes: %v", err)
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

		provider, err := acmedns.NewDNSProviderHostBytes(srv.URL, accountJSON, nil, wrongClient)
		if err != nil {
			t.Fatalf("NewDNSProviderHostBytes: %v", err)
		}

		err = provider.Present(t.Context(), "example.com", "example.com.", "LG3tptA6W7T1vw4ujbmDxH2lLu6r8TUIqLZD3pzPmgE")
		if err == nil {
			t.Fatal("expected TLS error when using wrong CA, got nil")
		}
	})
}
