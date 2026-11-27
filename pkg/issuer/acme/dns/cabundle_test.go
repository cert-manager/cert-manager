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
