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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func mustGenerateCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestBuildHTTPClientFromCABundle(t *testing.T) {
	validCAPEM := mustGenerateCAPEM(t)
	tests := map[string]struct {
		input     []byte
		wantNil   bool
		wantErr   bool
		errSubstr string
	}{
		"nil input returns nil client and nil error": {
			input:   nil,
			wantNil: true,
		},
		"empty input returns nil client and nil error": {
			input:   []byte{},
			wantNil: true,
		},
		"valid PEM returns non-nil client with configured TLS": {
			input:   validCAPEM,
			wantNil: false,
		},
		"invalid PEM returns error": {
			input:     []byte("not-a-cert"),
			wantNil:   true,
			wantErr:   true,
			errSubstr: "failed to parse caBundle",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := buildHTTPClientFromCABundle(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("expected error containing %q, got: %v", tc.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if tc.wantNil {
				if client != nil {
					t.Fatalf("expected nil client but got: %v", client)
				}
			} else {
				if client == nil {
					t.Fatalf("expected non-nil client but got nil")
				}
				transport, ok := client.Transport.(*http.Transport)
				if !ok {
					t.Fatalf("expected *http.Transport, got %T", client.Transport)
				}
				if transport.TLSClientConfig == nil {
					t.Fatal("expected TLSClientConfig to be non-nil")
				}
				if transport.TLSClientConfig.RootCAs == nil {
					t.Fatal("expected RootCAs to be non-nil")
				}
			}
		})
	}
}

func TestResolveCABundle(t *testing.T) {
	const (
		issuerName    = "test-issuer"
		ns            = "test-ns"
		clusterIssuer = "test-cluster-issuer"
	)

	perSolverBundle := []byte("per-solver-bundle")
	issuerBundle := []byte("issuer-bundle")

	buildSolverWithIssuers := func(t *testing.T, cmObjs ...runtime.Object) *Solver {
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

	tests := map[string]struct {
		challenge  *cmacme.Challenge
		cmObjects  []runtime.Object
		wantBundle []byte
		wantErr    bool
	}{
		"per-solver bundle overrides issuer bundle": {
			challenge: &cmacme.Challenge{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns},
				Spec: cmacme.ChallengeSpec{
					Solver: cmacme.ACMEChallengeSolver{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{
								CABundle: perSolverBundle,
							},
						},
					},
					IssuerRef: cmmeta.IssuerReference{
						Name: issuerName,
					},
				},
			},
			cmObjects: []runtime.Object{
				gen.Issuer(issuerName,
					gen.SetIssuerNamespace(ns),
					gen.SetIssuerACME(cmacme.ACMEIssuer{
						Server:   "https://acme.example.com",
						CABundle: issuerBundle,
					}),
				),
			},
			wantBundle: perSolverBundle,
		},
		"issuer bundle returned when per-solver bundle is empty": {
			challenge: &cmacme.Challenge{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns},
				Spec: cmacme.ChallengeSpec{
					Solver: cmacme.ACMEChallengeSolver{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{
								CABundle: nil,
							},
						},
					},
					IssuerRef: cmmeta.IssuerReference{
						Name: issuerName,
					},
				},
			},
			cmObjects: []runtime.Object{
				gen.Issuer(issuerName,
					gen.SetIssuerNamespace(ns),
					gen.SetIssuerACME(cmacme.ACMEIssuer{
						Server:   "https://acme.example.com",
						CABundle: issuerBundle,
					}),
				),
			},
			wantBundle: issuerBundle,
		},
		"nil returned when both per-solver and issuer bundles are empty": {
			challenge: &cmacme.Challenge{
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
			},
			cmObjects: []runtime.Object{
				gen.Issuer(issuerName,
					gen.SetIssuerNamespace(ns),
					gen.SetIssuerACME(cmacme.ACMEIssuer{
						Server: "https://acme.example.com",
					}),
				),
			},
			wantBundle: nil,
		},
		"per-solver bundle returned even when issuer lookup would fail": {
			challenge: &cmacme.Challenge{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns},
				Spec: cmacme.ChallengeSpec{
					Solver: cmacme.ACMEChallengeSolver{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{
								CABundle: perSolverBundle,
							},
						},
					},
					IssuerRef: cmmeta.IssuerReference{
						Name: "nonexistent-issuer",
					},
				},
			},
			cmObjects:  []runtime.Object{},
			wantBundle: perSolverBundle,
		},
		"error when per-solver bundle empty and issuer not found": {
			challenge: &cmacme.Challenge{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns},
				Spec: cmacme.ChallengeSpec{
					Solver: cmacme.ACMEChallengeSolver{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{},
						},
					},
					IssuerRef: cmmeta.IssuerReference{
						Name: "nonexistent-issuer",
					},
				},
			},
			cmObjects: []runtime.Object{},
			wantErr:   true,
		},
		"ClusterIssuer bundle returned when per-solver bundle is empty": {
			challenge: &cmacme.Challenge{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns},
				Spec: cmacme.ChallengeSpec{
					Solver: cmacme.ACMEChallengeSolver{
						DNS01: &cmacme.ACMEChallengeSolverDNS01{
							AcmeDNS: &cmacme.ACMEIssuerDNS01ProviderAcmeDNS{},
						},
					},
					IssuerRef: cmmeta.IssuerReference{
						Name: clusterIssuer,
						Kind: "ClusterIssuer",
					},
				},
			},
			cmObjects: []runtime.Object{
				gen.ClusterIssuer(clusterIssuer,
					gen.SetIssuerACME(cmacme.ACMEIssuer{
						Server:   "https://acme.example.com",
						CABundle: issuerBundle,
					}),
				),
			},
			wantBundle: issuerBundle,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			solver := buildSolverWithIssuers(t, tc.cmObjects...)
			bundle, err := solver.resolveCABundle(tc.challenge)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error but got nil (bundle=%v)", bundle)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(bundle) != string(tc.wantBundle) {
				t.Errorf("expected bundle %q, got %q", tc.wantBundle, bundle)
			}
		})
	}
}
