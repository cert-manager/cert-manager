/*
Copyright 2026 The cert-manager Authors.

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
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	testlisters "github.com/cert-manager/cert-manager/test/unit/listers"
)

func TestCA_Setup_MLDSA(t *testing.T) {
	ecdsaKey, err := pki.GenerateECPrivateKey(256)
	require.NoError(t, err)
	mldsaKey, err := pki.GenerateMLDSAPrivateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	tests := map[string]struct {
		key            crypto.Signer
		featureEnabled bool
		wantReady      cmmeta.ConditionStatus
		wantReason     string
		wantEvent      string
	}{
		"an ML-DSA CA should be Ready if the MLDSAPrivateKeys feature gate is enabled": {
			key:            mldsaKey,
			featureEnabled: true,
			wantReady:      cmmeta.ConditionTrue,
			wantReason:     successKeyPairVerified,
			wantEvent:      "Normal KeyPairVerified Signing CA verified",
		},
		"an ML-DSA CA should not be Ready if the MLDSAPrivateKeys feature gate is disabled": {
			key:        mldsaKey,
			wantReady:  cmmeta.ConditionFalse,
			wantReason: "MLDSAPrivateKeysDisabled",
			wantEvent:  "Warning MLDSAPrivateKeysDisabled Signing CA has an ML-DSA key, which requires the MLDSAPrivateKeys feature gate to be enabled",
		},
		"an ECDSA CA should be Ready if the MLDSAPrivateKeys feature gate is disabled": {
			key:        ecdsaKey,
			wantReady:  cmmeta.ConditionTrue,
			wantReason: successKeyPairVerified,
			wantEvent:  "Normal KeyPairVerified Signing CA verified",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultMutableFeatureGate, feature.MLDSAPrivateKeys, test.featureEnabled)

			tmpl := &x509.Certificate{
				BasicConstraintsValid: true,
				SerialNumber:          big.NewInt(0),
				Subject:               pkix.Name{CommonName: "root"},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(time.Minute),
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
				IsCA:                  true,
			}
			certPEM, _, err := pki.SignCertificate(tmpl, tmpl, test.key.Public(), test.key)
			require.NoError(t, err)
			keyPEM, err := pki.EncodePKCS8PrivateKey(test.key)
			require.NoError(t, err)

			rec := &testpkg.FakeRecorder{}
			c := &CA{
				Context: &controller.Context{Recorder: rec},
				secretsLister: testlisters.FakeSecretListerFrom(testlisters.NewFakeSecretLister(),
					testlisters.SetFakeSecretNamespaceListerGet(gen.Secret("ca-secret",
						gen.SetSecretNamespace("default"),
						gen.SetSecretData(map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM}),
					), nil),
				),
			}
			issuer := gen.Issuer("ca-issuer",
				gen.SetIssuerNamespace("default"),
				gen.SetIssuerCA(cmapi.CAIssuer{SecretName: "ca-secret"}),
			)

			require.NoError(t, c.Setup(t.Context(), issuer))

			require.Len(t, issuer.Status.Conditions, 1)
			assert.Equal(t, cmapi.IssuerConditionReady, issuer.Status.Conditions[0].Type)
			assert.Equal(t, test.wantReady, issuer.Status.Conditions[0].Status)
			assert.Equal(t, test.wantReason, issuer.Status.Conditions[0].Reason)
			assert.Equal(t, []string{test.wantEvent}, rec.Events)
		})
	}
}
