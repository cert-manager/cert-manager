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

package tls

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"

	"github.com/cert-manager/cert-manager/pkg/server/tls/authority"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// Integration tests for the DynamicSource can be found in `test/integration/webhook/dynamic_source_test.go`.

func signUsingTempCA(t *testing.T, template *x509.Certificate) *x509.Certificate {
	// generate random ca private key
	caPrivateKey, err := pki.GenerateECPrivateKey(521)
	if err != nil {
		t.Fatal(err)
	}

	caCRT := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	_, cert, err := pki.SignCertificate(template, caCRT, template.PublicKey.(crypto.PublicKey), caPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

type mockAuthority struct {
	doneCh   chan error
	notifyCh chan<- struct{}
	signFunc authority.SignFunc
}

func (m *mockAuthority) Run(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case err := <-m.doneCh:
		return err
	}
}

func (m *mockAuthority) WatchRotation(ch chan<- struct{}) {
	m.notifyCh = ch
}

func (m *mockAuthority) StopWatchingRotation(ch chan<- struct{}) {}

func (m *mockAuthority) Sign(template *x509.Certificate) (*x509.Certificate, error) {
	return m.signFunc(template)
}

func TestDynamicSource_FailingSign(t *testing.T) {
	type testCase struct {
		name        string
		signFunc    authority.SignFunc
		testFn      func(t *testing.T, source *DynamicSource, mockAuth *mockAuthority)
		cancelAtEnd bool
		expStartErr string
	}

	tests := []testCase{
		{
			name: "sign function returns error",
			signFunc: func(template *x509.Certificate) (*x509.Certificate, error) {
				return nil, fmt.Errorf("mock error")
			},
			testFn: func(t *testing.T, source *DynamicSource, mockAuth *mockAuthority) {
				// Call the GetCertificate method, should return a non-ready error
				cert, err := source.GetCertificate(&tls.ClientHelloInfo{})
				assert.Nil(t, cert)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "no tls.Certificate available")

				// The authority is now failing because of the faulty sign function,
				// we now stop the authority and wait for the DynamicSource to stop
				mockAuth.doneCh <- fmt.Errorf("mock error")
			},
			expStartErr: "mock error",
		},
		{
			name: "certificate authority stopped unexpectedly",
			signFunc: func(template *x509.Certificate) (*x509.Certificate, error) {
				return nil, fmt.Errorf("mock error")
			},
			testFn: func(t *testing.T, source *DynamicSource, mockAuth *mockAuthority) {
				// Stop the authority
				mockAuth.doneCh <- nil
			},
			expStartErr: "certificate authority stopped unexpectedly",
		},
		{
			name: "sign function returns error (retry, then success)",
			signFunc: func() authority.SignFunc {
				var called int
				return func(template *x509.Certificate) (*x509.Certificate, error) {
					called++
					if called != 5 {
						return nil, fmt.Errorf("mock error")
					}

					template.Version = 3
					template.SerialNumber = big.NewInt(10)
					template.NotBefore = time.Now()
					template.NotAfter = template.NotBefore.Add(time.Minute)

					return signUsingTempCA(t, template), nil
				}
			}(),
			testFn: func(t *testing.T, source *DynamicSource, mockAuth *mockAuthority) {
				for !source.Healthy() {
					time.Sleep(50 * time.Millisecond)
				}

				// Call the GetCertificate method, should return a certificate
				cert, err := source.GetCertificate(&tls.ClientHelloInfo{})
				assert.NoError(t, err)
				assert.NotNil(t, cert)
			},
			cancelAtEnd: true,
		},
		{
			name: "don't rotate root",
			signFunc: func(template *x509.Certificate) (*x509.Certificate, error) {
				template.Version = 3
				template.SerialNumber = big.NewInt(10)
				template.NotBefore = time.Now()
				template.NotAfter = template.NotBefore.Add(time.Minute)

				return signUsingTempCA(t, template), nil
			},
			testFn: func(t *testing.T, source *DynamicSource, mockAuth *mockAuthority) {
				for !source.Healthy() {
					time.Sleep(50 * time.Millisecond)
				}

				// Call the GetCertificate method, should return a certificate
				cert, err := source.GetCertificate(&tls.ClientHelloInfo{})
				assert.NoError(t, err)
				assert.NotNil(t, cert)

				// Sleep for a short time to allow the DynamicSource to generate a new certificate
				// Which it should not do, as the root CA has not been rotated
				time.Sleep(50 * time.Millisecond)

				// Call the GetCertificate method, should return a NEW certificate
				cert2, err := source.GetCertificate(&tls.ClientHelloInfo{})
				assert.NoError(t, err)
				assert.NotNil(t, cert2)

				assert.Equal(t, cert.Certificate[0], cert2.Certificate[0])
			},
			cancelAtEnd: true,
		},
		{
			name: "rotate root",
			signFunc: func(template *x509.Certificate) (*x509.Certificate, error) {
				template.Version = 3
				template.SerialNumber = big.NewInt(10)
				template.NotBefore = time.Now()
				template.NotAfter = template.NotBefore.Add(time.Minute)

				return signUsingTempCA(t, template), nil
			},
			testFn: func(t *testing.T, source *DynamicSource, mockAuth *mockAuthority) {
				for !source.Healthy() {
					time.Sleep(50 * time.Millisecond)
				}

				// Call the GetCertificate method, should return a certificate
				cert, err := source.GetCertificate(&tls.ClientHelloInfo{})
				assert.NoError(t, err)
				assert.NotNil(t, cert)

				for i := 0; i < 10; i++ {
					// Rotate the root
					mockAuth.notifyCh <- struct{}{}

					// Sleep for a short time to allow the DynamicSource to generate a new certificate
					time.Sleep(50 * time.Millisecond)

					// Call the GetCertificate method, should return a NEW certificate
					cert2, err := source.GetCertificate(&tls.ClientHelloInfo{})
					assert.NoError(t, err)
					assert.NotNil(t, cert2)

					assert.NotEqual(t, cert.Certificate[0], cert2.Certificate[0])
				}
			},
			cancelAtEnd: true,
		},
		{
			name: "expire leaf",
			signFunc: func(template *x509.Certificate) (*x509.Certificate, error) {
				template.Version = 3
				template.SerialNumber = big.NewInt(10)
				template.NotBefore = time.Now()
				template.NotAfter = template.NotBefore.Add(150 * time.Millisecond)

				signedCert := signUsingTempCA(t, template)
				// Reset the NotBefore and NotAfter so we have high precision values here
				signedCert.NotBefore = time.Now()
				signedCert.NotAfter = signedCert.NotBefore.Add(150 * time.Millisecond)

				// Should renew at 100ms after the NotBefore time

				return signedCert, nil
			},
			testFn: func(t *testing.T, source *DynamicSource, mockAuth *mockAuthority) {
				for !source.Healthy() {
					time.Sleep(50 * time.Millisecond)
				}

				// Call the GetCertificate method, should return a certificate
				cert, err := source.GetCertificate(&tls.ClientHelloInfo{})
				assert.NoError(t, err)
				assert.NotNil(t, cert)

				for i := 0; i < 5; i++ {
					// Sleep for a short time to allow the DynamicSource to generate a new certificate
					// The certificate should get renewed after 100ms, we wait for 200ms to allow for
					// possible delays of max 100ms (based on experiments, we noticed that issuance of
					// a cert takes about 30ms, so 100ms should be a large enough margin).
					time.Sleep(200 * time.Millisecond)

					// Call the GetCertificate method, should return a NEW certificate
					newCert, err := source.GetCertificate(&tls.ClientHelloInfo{})
					assert.NoError(t, err)
					assert.NotNil(t, newCert)

					assert.NotEqual(t, cert.Certificate[0], newCert.Certificate[0])

					cert = newCert
				}
			},
			cancelAtEnd: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create a mock authority
			mockAuth := &mockAuthority{
				doneCh:   make(chan error),
				signFunc: tc.signFunc,
			}

			// Create a DynamicSource instance with the mock authority
			source := &DynamicSource{
				Authority:     mockAuth,
				RetryInterval: 1 * time.Millisecond,
			}

			// Start the DynamicSource
			ctx, cancel := context.WithCancel(context.Background())
			group, gctx := errgroup.WithContext(ctx)
			group.Go(func() error {
				return source.Start(gctx)
			})
			t.Cleanup(func() {
				if tc.cancelAtEnd {
					cancel()
				} else {
					defer cancel()
				}
				err := group.Wait()
				if tc.expStartErr == "" {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.expStartErr)
				}
			})

			tc.testFn(t, source, mockAuth)
		})
	}
}
