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

package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	cmv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificaterequests/ca"
	controllertest "github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/unit/gen"
	"github.com/jetstack/cert-manager/test/unit/listers"
)

func TestCA_Setup(t *testing.T) {
	caCrt, caKey := mustGenerateTLSAssets(t)
	tests := map[string]struct {
		givenNamespace string
		givenSecret    *corev1.Secret
		givenIssuer    cmv1.GenericIssuer
		wantCert       *cmv1.Certificate
		wantErr        error
	}{
		"a": {
			givenIssuer: &cmv1.Issuer{
				Spec: cmv1.IssuerSpec{IssuerConfig: cmv1.IssuerConfig{
					CA: &cmv1.CAIssuer{
						SecretName:  "secret-1",
						OCSPServers: []string{"http://ocsp-v3.example.org"},
					},
				}},
			},
			givenSecret: gen.SecretFrom(gen.Secret("secret-1"),
				gen.SetSecretNamespace("default"),
				gen.SetSecretData(map[string][]byte{
					"tls.key": caKey,
					"tls.crt": caCrt,
				}),
			),
			givenNamespace: "default",
			wantErr:        nil,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &controllertest.FakeRecorder{}

			c := &CA{
				Context: &controller.Context{
					Recorder: rec,
				},
				issuer:            test.givenIssuer,
				resourceNamespace: test.givenNamespace,
				secretsLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
					listers.SetFakeSecretNamespaceListerGet(test.givenSecret, nil),
				),
			}

			err := c.Setup(context.Background())
			// TODO: How do I c.Issue()? The ca.CA struct only implements
			// the Setup function, not the Issue function.

			if test.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, test.wantErr, err)
			}
			require.NoError(t, err)
		})
	}
}

// Returns a PEM-formated CA certificate and its key.
func mustGenerateTLSAssets(t *testing.T) (caCrt, caKey []byte) {
	caPK, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
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
	require.NoError(t, err)
	rootCA, err = x509.ParseCertificate(rootCADER)
	require.NoError(t, err)

	// encoding PKI data to PEM
	caKey, err = pki.EncodePKCS8PrivateKey(caPK)
	require.NoError(t, err)
	caCrt, err = pki.EncodeX509(rootCA)
	require.NoError(t, err)

	return caCrt, caKey
}
