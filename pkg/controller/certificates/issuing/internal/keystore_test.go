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

package internal

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"testing"

	fuzz "github.com/google/gofuzz"
	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"software.sslmate.com/src/go-pkcs12"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func mustGeneratePrivateKey(t *testing.T, encoding cmapi.PrivateKeyEncoding) []byte {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pkBytes, err := pki.EncodePrivateKey(pk, encoding)
	if err != nil {
		t.Fatal(err)
	}
	return pkBytes
}

func mustSelfSignCertificate(t *testing.T) []byte {
	pkBytes := mustGeneratePrivateKey(t, cmapi.PKCS8)
	pk, err := pki.DecodePrivateKeyBytes(pkBytes)
	if err != nil {
		t.Fatal(err)
	}
	x509Crt, err := pki.CertificateTemplateFromCertificate(&cmapi.Certificate{
		Spec: cmapi.CertificateSpec{
			DNSNames: []string{"example.com"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	certBytes, _, err := pki.SignCertificate(x509Crt, x509Crt, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	return certBytes
}

func mustSelfSignCertificates(t *testing.T, count int) []byte {
	var buf bytes.Buffer
	for i := 0; i < count; i++ {
		buf.Write(mustSelfSignCertificate(t))
	}
	return buf.Bytes()
}

type keyAndCert struct {
	key     crypto.Signer
	keyPEM  []byte
	cert    *x509.Certificate
	certPEM []byte
}

func mustCert(t *testing.T, commonName string, isCA bool) *keyAndCert {
	key, err := pki.GenerateRSAPrivateKey(2048)
	require.NoError(t, err)
	keyPEM, err := pki.EncodePrivateKey(key, cmapi.PKCS8)
	require.NoError(t, err)

	cert, err := pki.CertificateTemplateFromCertificate(&cmapi.Certificate{
		Spec: cmapi.CertificateSpec{
			CommonName: commonName,
			IsCA:       isCA,
		},
	})
	require.NoError(t, err)

	return &keyAndCert{
		key:    key,
		keyPEM: keyPEM,
		cert:   cert,
	}
}

func (o *keyAndCert) mustSign(t *testing.T, ca *keyAndCert) {
	require.True(t, ca.cert.IsCA, "not a CA", ca.cert)
	var err error
	o.certPEM, o.cert, err = pki.SignCertificate(o.cert, ca.cert, o.key.Public(), ca.key)
	require.NoError(t, err)
}

type certChain []*keyAndCert

func (o certChain) certsToPEM() (certs []byte) {
	for _, kc := range o {
		certs = append(certs, kc.certPEM...)
	}
	return
}

type leafWithChain struct {
	all  certChain
	leaf *keyAndCert
	cas  certChain
}

const chainLength = 3

func mustLeafWithChain(t *testing.T) leafWithChain {
	all := make(certChain, chainLength)

	var last *keyAndCert
	for i := range all {
		isCA := i > 0
		commonName := fmt.Sprintf("Cert %d of %d", i+1, chainLength)
		c := mustCert(t, commonName, isCA)
		if last != nil {
			last.mustSign(t, c)
		}
		last = c
		all[i] = c
	}
	last.mustSign(t, last)

	return leafWithChain{
		all:  all,
		leaf: all[0],
		cas:  all[1:],
	}
}

func TestEncodeJKSKeystore(t *testing.T) {
	tests := map[string]struct {
		password               string
		alias                  string
		rawKey, certPEM, caPEM []byte
		verify                 func(t *testing.T, out []byte, err error)
	}{
		"encode a JKS bundle for a PKCS1 key and certificate only": {
			password: "password",
			alias:    "alias",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS1),
			certPEM:  mustSelfSignCertificate(t),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
					return
				}
				buf := bytes.NewBuffer(out)
				ks := jks.New()
				err = ks.Load(buf, []byte("password"))
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}

				if !ks.IsPrivateKeyEntry("alias") {
					t.Errorf("no certificate data found in keystore")
				}

				if ks.IsTrustedCertificateEntry("ca") {
					t.Errorf("unexpected ca data found in truststore")
				}
			},
		},
		"encode a JKS bundle for a PKCS8 key and certificate only": {
			password: "password",
			alias:    "alias",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS8),
			certPEM:  mustSelfSignCertificate(t),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				buf := bytes.NewBuffer(out)
				ks := jks.New()
				err = ks.Load(buf, []byte("password"))
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if !ks.IsPrivateKeyEntry("alias") {
					t.Errorf("no certificate data found in keystore")
				}

				if ks.IsTrustedCertificateEntry("ca") {
					t.Errorf("unexpected ca data found in truststore")
				}
			},
		},
		"encode a JKS bundle for a key, certificate and ca": {
			password: "password",
			alias:    "alias",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS8),
			certPEM:  mustSelfSignCertificate(t),
			caPEM:    mustSelfSignCertificate(t),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				buf := bytes.NewBuffer(out)
				ks := jks.New()
				err = ks.Load(buf, []byte("password"))
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if !ks.IsPrivateKeyEntry("alias") {
					t.Errorf("no certificate data found in keystore")
				}
				if !ks.IsTrustedCertificateEntry("ca") {
					t.Errorf("no ca data found in truststore")
				}
			},
		},
		"encode a JKS bundle for a key, certificate and multiple cas": {
			password: "password",
			alias:    "alias",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS8),
			certPEM:  mustSelfSignCertificate(t),
			caPEM:    mustSelfSignCertificates(t, 3),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				buf := bytes.NewBuffer(out)
				ks := jks.New()
				err = ks.Load(buf, []byte("password"))
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if !ks.IsPrivateKeyEntry("alias") {
					t.Errorf("no certificate data found in keystore")
				}
				if !ks.IsTrustedCertificateEntry("ca") {
					t.Errorf("no ca data found in truststore")
				}
				if !ks.IsTrustedCertificateEntry("ca-1") {
					t.Errorf("no ca data found in truststore")
				}
				if !ks.IsTrustedCertificateEntry("ca-2") {
					t.Errorf("no ca data found in truststore")
				}
				if len(ks.Aliases()) != 4 {
					t.Errorf("expected 4 aliases in keystore, got %d", len(ks.Aliases()))
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := encodeJKSKeystore([]byte(test.password), test.alias, test.rawKey, test.certPEM, test.caPEM)
			test.verify(t, out, err)
		})
	}
}

func TestEncodeJKSTruststore(t *testing.T) {
	tests := map[string]struct {
		password string
		caCount  int
		verify   func(t *testing.T, out []byte, err error)
	}{
		"encode a JKS truststore for a single ca": {
			password: "password",
			caCount:  1,
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				buf := bytes.NewBuffer(out)
				ks := jks.New()
				err = ks.Load(buf, []byte("password"))
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if !ks.IsTrustedCertificateEntry("ca") {
					t.Errorf("no ca data found in truststore")
				}
				if len(ks.Aliases()) != 1 {
					t.Errorf("expected 1 alias in keystore, got %d", len(ks.Aliases()))
				}
			},
		},
		"encode a JKS truststore for multiple cas": {
			password: "password",
			caCount:  3,
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				buf := bytes.NewBuffer(out)
				ks := jks.New()
				err = ks.Load(buf, []byte("password"))
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if !ks.IsTrustedCertificateEntry("ca") {
					t.Errorf("no ca data found in truststore")
				}
				if !ks.IsTrustedCertificateEntry("ca-1") {
					t.Errorf("no ca data found in truststore")
				}
				if !ks.IsTrustedCertificateEntry("ca-2") {
					t.Errorf("no ca data found in truststore")
				}
				if len(ks.Aliases()) != 3 {
					t.Errorf("expected 3 aliases in keystore, got %d", len(ks.Aliases()))
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := encodeJKSTruststore([]byte(test.password), mustSelfSignCertificates(t, test.caCount))
			test.verify(t, out, err)
		})
	}
}

func TestEncodePKCS12Keystore(t *testing.T) {
	tests := map[string]struct {
		password               string
		rawKey, certPEM, caPEM []byte
		verify                 func(t *testing.T, out []byte, err error)
		run                    func(t testing.T)
	}{
		"encode a JKS bundle for a PKCS1 key and certificate only": {
			password: "password",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS1),
			certPEM:  mustSelfSignCertificate(t),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				pk, cert, err := pkcs12.Decode(out, "password")
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if cert == nil {
					t.Errorf("no certificate data found in keystore")
				}
				if pk == nil {
					t.Errorf("no ca data found in keystore")
				}
			},
		},
		"encode a JKS bundle for a PKCS8 key and certificate only": {
			password: "password",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS8),
			certPEM:  mustSelfSignCertificate(t),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				pk, cert, err := pkcs12.Decode(out, "password")
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if cert == nil {
					t.Errorf("no certificate data found in keystore")
				}
				if pk == nil {
					t.Errorf("no ca data found in keystore")
				}
			},
		},
		"encode a JKS bundle for a key, certificate and ca": {
			password: "password",
			rawKey:   mustGeneratePrivateKey(t, cmapi.PKCS8),
			certPEM:  mustSelfSignCertificate(t),
			caPEM:    mustSelfSignCertificate(t),
			verify: func(t *testing.T, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				pk, cert, caCerts, err := pkcs12.DecodeChain(out, "password")
				if err != nil {
					t.Errorf("error decoding keystore: %v", err)
					return
				}
				if cert == nil {
					t.Errorf("no certificate data found in keystore")
				}
				if pk == nil {
					t.Errorf("no private key data found in keystore")
				}
				if caCerts == nil {
					t.Errorf("no ca data found in keystore")
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for _, profile := range []cmapi.PKCS12Profile{"", cmapi.LegacyRC2PKCS12Profile, cmapi.LegacyDESPKCS12Profile, cmapi.Modern2023PKCS12Profile} {
				out, err := encodePKCS12Keystore(profile, test.password, test.rawKey, test.certPEM, test.caPEM)
				test.verify(t, out, err)
			}
		})
	}
	t.Run("encodePKCS12Keystore encodes non-leaf certificates to the CA certificate chain, even when the supplied CA chain is empty", func(t *testing.T) {
		const password = "password"
		var emptyCAChain []byte = nil

		chain := mustLeafWithChain(t)
		for _, profile := range []cmapi.PKCS12Profile{"", cmapi.LegacyRC2PKCS12Profile, cmapi.LegacyDESPKCS12Profile, cmapi.Modern2023PKCS12Profile} {
			out, err := encodePKCS12Keystore(profile, password, chain.leaf.keyPEM, chain.all.certsToPEM(), emptyCAChain)
			require.NoError(t, err)

			pkOut, certOut, caChain, err := pkcs12.DecodeChain(out, password)
			require.NoError(t, err)
			assert.NotNil(t, pkOut)
			assert.Equal(t, chain.leaf.cert.Signature, certOut.Signature, "leaf certificate signature does not match")
			if assert.Len(t, caChain, 2, "caChain should contain 2 items: intermediate certificate and top-level certificate") {
				assert.Equal(t, chain.cas[0].cert.Signature, caChain[0].Signature, "intermediate certificate signature does not match")
				assert.Equal(t, chain.cas[1].cert.Signature, caChain[1].Signature, "top-level certificate signature does not match")
			}
		}
	})
	t.Run("encodePKCS12Keystore *prepends* non-leaf certificates to the supplied CA certificate chain", func(t *testing.T) {
		const password = "password"
		caChainInPEM := mustSelfSignCertificate(t)
		caChainIn, err := pki.DecodeX509CertificateChainBytes(caChainInPEM)
		require.NoError(t, err)

		chain := mustLeafWithChain(t)
		for _, profile := range []cmapi.PKCS12Profile{"", cmapi.LegacyRC2PKCS12Profile, cmapi.LegacyDESPKCS12Profile, cmapi.Modern2023PKCS12Profile} {
			out, err := encodePKCS12Keystore(profile, password, chain.leaf.keyPEM, chain.all.certsToPEM(), caChainInPEM)
			require.NoError(t, err)

			pkOut, certOut, caChainOut, err := pkcs12.DecodeChain(out, password)
			require.NoError(t, err)
			assert.NotNil(t, pkOut)
			assert.Equal(t, chain.leaf.cert.Signature, certOut.Signature, "leaf certificate signature does not match")
			if assert.Len(t, caChainOut, 3, "caChain should contain 3 items: intermediate certificate and top-level certificate and supplied CA") {
				assert.Equal(t, chain.cas[0].cert.Signature, caChainOut[0].Signature, "intermediate certificate signature does not match")
				assert.Equal(t, chain.cas[1].cert.Signature, caChainOut[1].Signature, "top-level certificate signature does not match")
				assert.Equal(t, caChainIn, caChainOut[2:], "supplied certificate chain is not at the end of the chain")
			}
		}
	})
}

func TestEncodePKCS12Truststore(t *testing.T) {
	tests := map[string]struct {
		password string
		caPEM    []byte
		verify   func(t *testing.T, caPEM []byte, out []byte, err error)
		run      func(t testing.T)
	}{
		"encode a PKCS12 bundle for a CA": {
			password: "password",
			caPEM:    mustSelfSignCertificates(t, 1),
			verify: func(t *testing.T, caPEM []byte, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				certs, err := pkcs12.DecodeTrustStore(out, "password")
				if err != nil {
					t.Errorf("error decoding truststore: %v", err)
					return
				}
				if certs == nil {
					t.Errorf("no certificates found in truststore")
				}
				if assert.Len(t, certs, 1, "Trusted CA certificates should include 1 entry") {
					ca, err := pki.DecodeX509CertificateBytes(caPEM)
					require.NoError(t, err)
					assert.Equal(t, ca.Signature, certs[0].Signature, "Trusted CA certificate signature does not match")
				}
			},
		},
		"encode a PKCS12 bundle for multiple CAs": {
			password: "password",
			caPEM:    mustSelfSignCertificates(t, 3),
			verify: func(t *testing.T, caPEM []byte, out []byte, err error) {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				certs, err := pkcs12.DecodeTrustStore(out, "password")
				if err != nil {
					t.Errorf("error decoding truststore: %v", err)
					return
				}
				if certs == nil {
					t.Errorf("no certificates found in truststore")
				}
				if len(certs) != 3 {
					t.Errorf("Trusted CA certificates should include 3 entries, got %d", len(certs))
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for _, profile := range []cmapi.PKCS12Profile{"", cmapi.LegacyRC2PKCS12Profile, cmapi.LegacyDESPKCS12Profile, cmapi.Modern2023PKCS12Profile} {
				out, err := encodePKCS12Truststore(profile, test.password, test.caPEM)
				test.verify(t, test.caPEM, out, err)
			}
		})
	}
}

func TestManyPasswordLengths(t *testing.T) {
	rawKey := mustGeneratePrivateKey(t, cmapi.PKCS8)
	certPEM := mustSelfSignCertificate(t)
	caPEM := mustSelfSignCertificate(t)

	const testN = 10000

	// We will test random password lengths between 0 and 128 character lengths
	f := fuzz.New().NilChance(0).NumElements(0, 128)
	// Pre-create password test cases. This cannot be done during the test itself
	// since the fuzzer cannot be used concurrently.
	var passwords [testN]string
	for testi := 0; testi < testN; testi++ {
		// fill the password with random characters
		f.Fuzz(&passwords[testi])
	}

	// Run these tests in parallel
	s := semaphore.NewWeighted(32)
	g, ctx := errgroup.WithContext(context.Background())
	for tests := 0; tests < testN; tests++ {
		testi := tests
		if ctx.Err() != nil {
			t.Errorf("internal error while testing JKS Keystore password lengths: %s", ctx.Err())
			return
		}
		if err := s.Acquire(ctx, 1); err != nil {
			t.Errorf("internal error while testing JKS Keystore password lengths: %s", err.Error())
			return
		}
		g.Go(func() error {
			defer s.Release(1)
			keystore, err := encodeJKSKeystore([]byte(passwords[testi]), "alias", rawKey, certPEM, caPEM)
			if err != nil {
				t.Errorf("couldn't encode JKS Keystore with password %s (length %d): %s", passwords[testi], len(passwords[testi]), err.Error())
				return err
			}

			buf := bytes.NewBuffer(keystore)
			ks := jks.New()
			err = ks.Load(buf, []byte(passwords[testi]))
			if err != nil {
				t.Errorf("error decoding keystore with password %s (length %d): %v", passwords[testi], len(passwords[testi]), err)
				return err
			}
			if !ks.IsPrivateKeyEntry("alias") {
				t.Errorf("no certificate data found in keystore")
			}
			if !ks.IsTrustedCertificateEntry("ca") {
				t.Errorf("no ca data found in truststore")
			}

			return nil
		})
	}
	err := g.Wait()
	assert.NoError(t, err)
}
