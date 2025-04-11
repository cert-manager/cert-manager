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

package shimhelper

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmutil "github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_translateAnnotations(t *testing.T) {
	type testCase struct {
		crt           *cmapi.Certificate
		annotations   map[string]string
		mutate        func(*testCase)
		check         func(*assert.Assertions, *cmapi.Certificate)
		expectedError error
	}

	validAnnotations := func() map[string]string {
		return map[string]string{
			cmapi.CommonNameAnnotationKey:                 "www.example.com",
			cmapi.DurationAnnotationKey:                   "168h", // 1 week
			cmapi.RenewBeforeAnnotationKey:                "24h",
			cmapi.UsagesAnnotationKey:                     "server auth,signing",
			cmapi.RevisionHistoryLimitAnnotationKey:       "7",
			cmapi.EmailsAnnotationKey:                     "test@example.com",
			cmapi.SubjectOrganizationsAnnotationKey:       "Test Organization",
			cmapi.SubjectOrganizationalUnitsAnnotationKey: "Test Organizational Unit",
			cmapi.SubjectCountriesAnnotationKey:           "Country",
			cmapi.SubjectProvincesAnnotationKey:           "Province",
			cmapi.SubjectLocalitiesAnnotationKey:          "City",
			cmapi.SubjectStreetAddressesAnnotationKey:     `"1725 Slough Avenue, Suite 200, Scranton Business Park","1800 Slough Avenue, Suite 200, Scranton Business Park"`,
			cmapi.SubjectPostalCodesAnnotationKey:         "ABC123",
			cmapi.SubjectSerialNumberAnnotationKey:        "123456",
		}
	}

	tests := map[string]testCase{
		"success": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			check: func(a *assert.Assertions, crt *cmapi.Certificate) {
				a.Equal("www.example.com", crt.Spec.CommonName)
				a.Equal(&metav1.Duration{Duration: time.Hour * 24 * 7}, crt.Spec.Duration)
				a.Equal(&metav1.Duration{Duration: time.Hour * 24}, crt.Spec.RenewBefore)
				a.Equal([]cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageSigning}, crt.Spec.Usages)
				a.Equal(ptr.To(int32(7)), crt.Spec.RevisionHistoryLimit)
				a.Equal("123456", crt.Spec.Subject.SerialNumber)

				splitAddresses, splitErr := cmutil.SplitWithEscapeCSV(`"1725 Slough Avenue, Suite 200, Scranton Business Park","1800 Slough Avenue, Suite 200, Scranton Business Park"`)
				a.Equal(nil, splitErr)
				a.Equal(splitAddresses, crt.Spec.Subject.StreetAddresses)

				joinedAddresses, joinErr := cmutil.JoinWithEscapeCSV(crt.Spec.Subject.StreetAddresses)
				a.Equal(nil, joinErr)
				a.Equal(`"1725 Slough Avenue, Suite 200, Scranton Business Park","1800 Slough Avenue, Suite 200, Scranton Business Park"`, joinedAddresses)
			},
		},
		"success renew before pct": {
			crt: gen.Certificate("example-cert"),
			annotations: map[string]string{
				cmapi.CommonNameAnnotationKey:               "www.example.com",
				cmapi.DurationAnnotationKey:                 "168h", // 1 week
				cmapi.RenewBeforePercentageAnnotationKey:    "50",
				cmapi.UsagesAnnotationKey:                   "server auth,signing",
				cmapi.PrivateKeyAlgorithmAnnotationKey:      "RSA",
				cmapi.PrivateKeyEncodingAnnotationKey:       "PKCS1",
				cmapi.PrivateKeySizeAnnotationKey:           "2048",
				cmapi.PrivateKeyRotationPolicyAnnotationKey: "Always",
			},
			check: func(a *assert.Assertions, crt *cmapi.Certificate) {
				a.Equal("www.example.com", crt.Spec.CommonName)
				a.Equal(&metav1.Duration{Duration: time.Hour * 24 * 7}, crt.Spec.Duration)
				a.Equal(ptr.To(int32(50)), crt.Spec.RenewBeforePercentage)
				a.Equal([]cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageSigning}, crt.Spec.Usages)
				a.Equal(cmapi.RSAKeyAlgorithm, crt.Spec.PrivateKey.Algorithm)
				a.Equal(cmapi.PKCS1, crt.Spec.PrivateKey.Encoding)
				a.Equal(2048, crt.Spec.PrivateKey.Size)
				a.Equal(cmapi.RotationPolicyAlways, crt.Spec.PrivateKey.RotationPolicy)
			},
		},
		"success rsa private key algorithm": {
			crt: gen.Certificate("example-cert"),
			annotations: map[string]string{
				cmapi.CommonNameAnnotationKey:               "www.example.com",
				cmapi.DurationAnnotationKey:                 "168h", // 1 week
				cmapi.RenewBeforeAnnotationKey:              "24h",
				cmapi.UsagesAnnotationKey:                   "server auth,signing",
				cmapi.PrivateKeyAlgorithmAnnotationKey:      "RSA",
				cmapi.PrivateKeyEncodingAnnotationKey:       "PKCS1",
				cmapi.PrivateKeySizeAnnotationKey:           "2048",
				cmapi.PrivateKeyRotationPolicyAnnotationKey: "Always",
			},
			check: func(a *assert.Assertions, crt *cmapi.Certificate) {
				a.Equal("www.example.com", crt.Spec.CommonName)
				a.Equal(&metav1.Duration{Duration: time.Hour * 24 * 7}, crt.Spec.Duration)
				a.Equal(&metav1.Duration{Duration: time.Hour * 24}, crt.Spec.RenewBefore)
				a.Equal([]cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageSigning}, crt.Spec.Usages)
				a.Equal(cmapi.RSAKeyAlgorithm, crt.Spec.PrivateKey.Algorithm)
				a.Equal(cmapi.PKCS1, crt.Spec.PrivateKey.Encoding)
				a.Equal(2048, crt.Spec.PrivateKey.Size)
				a.Equal(cmapi.RotationPolicyAlways, crt.Spec.PrivateKey.RotationPolicy)
			},
		},
		"success ecdsa private key algorithm": {
			crt: gen.Certificate("example-cert"),
			annotations: map[string]string{
				cmapi.CommonNameAnnotationKey:               "www.example.com",
				cmapi.DurationAnnotationKey:                 "168h", // 1 week
				cmapi.RenewBeforeAnnotationKey:              "24h",
				cmapi.UsagesAnnotationKey:                   "server auth,signing",
				cmapi.PrivateKeyAlgorithmAnnotationKey:      "ECDSA",
				cmapi.PrivateKeyEncodingAnnotationKey:       "PKCS1",
				cmapi.PrivateKeySizeAnnotationKey:           "256",
				cmapi.PrivateKeyRotationPolicyAnnotationKey: "Always",
			},
			check: func(a *assert.Assertions, crt *cmapi.Certificate) {
				a.Equal("www.example.com", crt.Spec.CommonName)
				a.Equal(&metav1.Duration{Duration: time.Hour * 24 * 7}, crt.Spec.Duration)
				a.Equal(&metav1.Duration{Duration: time.Hour * 24}, crt.Spec.RenewBefore)
				a.Equal([]cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageSigning}, crt.Spec.Usages)
				a.Equal(cmapi.ECDSAKeyAlgorithm, crt.Spec.PrivateKey.Algorithm)
				a.Equal(cmapi.PKCS1, crt.Spec.PrivateKey.Encoding)
				a.Equal(256, crt.Spec.PrivateKey.Size)
				a.Equal(cmapi.RotationPolicyAlways, crt.Spec.PrivateKey.RotationPolicy)
			},
		},
		"success ed25519 private key algorithm": {
			crt: gen.Certificate("example-cert"),
			annotations: map[string]string{
				cmapi.CommonNameAnnotationKey:               "www.example.com",
				cmapi.DurationAnnotationKey:                 "168h", // 1 week
				cmapi.RenewBeforeAnnotationKey:              "24h",
				cmapi.UsagesAnnotationKey:                   "server auth,signing",
				cmapi.PrivateKeyAlgorithmAnnotationKey:      "Ed25519",
				cmapi.PrivateKeyEncodingAnnotationKey:       "PKCS8",
				cmapi.PrivateKeyRotationPolicyAnnotationKey: "Always",
			},
			check: func(a *assert.Assertions, crt *cmapi.Certificate) {
				a.Equal("www.example.com", crt.Spec.CommonName)
				a.Equal(&metav1.Duration{Duration: time.Hour * 24 * 7}, crt.Spec.Duration)
				a.Equal(&metav1.Duration{Duration: time.Hour * 24}, crt.Spec.RenewBefore)
				a.Equal([]cmapi.KeyUsage{cmapi.UsageServerAuth, cmapi.UsageSigning}, crt.Spec.Usages)
				a.Equal(cmapi.Ed25519KeyAlgorithm, crt.Spec.PrivateKey.Algorithm)
				a.Equal(cmapi.PKCS8, crt.Spec.PrivateKey.Encoding)
				a.Equal(cmapi.RotationPolicyAlways, crt.Spec.PrivateKey.RotationPolicy)
			},
		},
		"nil annotations": {
			crt:         gen.Certificate("example-cert"),
			annotations: nil,
		},
		"empty annotations": {
			crt:         gen.Certificate("example-cert"),
			annotations: map[string]string{},
		},
		"nil certificate": {
			crt:           nil,
			annotations:   validAnnotations(),
			expectedError: errNilCertificate,
		},
		"bad duration": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.DurationAnnotationKey] = "an un-parsable duration string"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad renewBefore": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.RenewBeforeAnnotationKey] = "an un-parsable duration string"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad renewBeforePercentage": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.RenewBeforePercentageAnnotationKey] = "an un-parsable integer"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad usages": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.UsagesAnnotationKey] = "playing ping pong"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad usage list": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.UsagesAnnotationKey] = "server auth,,signing"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad revision history limit": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.RevisionHistoryLimitAnnotationKey] = "invalid revision history limit"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"zero revision history limit": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.RevisionHistoryLimitAnnotationKey] = "0"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad private key algorithm": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.PrivateKeyAlgorithmAnnotationKey] = "invalid private key algorithm"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad private key encoding": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.PrivateKeyEncodingAnnotationKey] = "invalid private key encoding"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad private key rotation policy": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.PrivateKeyRotationPolicyAnnotationKey] = "invalid private key rotation policy"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad private key size": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.PrivateKeySizeAnnotationKey] = "invalid private key size"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"zero private key size": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.PrivateKeySizeAnnotationKey] = "0"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad private key size for rsa": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.PrivateKeyAlgorithmAnnotationKey] = "RSA"
				tc.annotations[cmapi.PrivateKeySizeAnnotationKey] = "1024"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad private key size for ecdsa": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.PrivateKeyAlgorithmAnnotationKey] = "ECDSA"
				tc.annotations[cmapi.PrivateKeySizeAnnotationKey] = "128"
			},
			expectedError: errInvalidIngressAnnotation,
		},
		"bad street addresses": {
			crt:         gen.Certificate("example-cert"),
			annotations: validAnnotations(),
			mutate: func(tc *testCase) {
				tc.annotations[cmapi.SubjectStreetAddressesAnnotationKey] = "invalid csv\","
			},
			expectedError: errInvalidIngressAnnotation,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.mutate != nil {
				tc.mutate(&tc)
			}
			crt := tc.crt.DeepCopy()

			err := translateAnnotations(crt, tc.annotations)

			if tc.expectedError != nil {
				assertErrorIs(t, err, tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
			if tc.check != nil {
				tc.check(assert.New(t), crt)
			}
		})
	}
}

// assertErrorIs checks that the supplied error has the target error in its chain.
// TODO Upgrade to next release of testify package which has this built in.
func assertErrorIs(t *testing.T, err, target error) {
	if assert.Error(t, err) {
		assert.Truef(t, errors.Is(err, target), "unexpected error type. err: %v, target: %v", err, target)
	}
}
