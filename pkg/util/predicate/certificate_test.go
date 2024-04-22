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

package predicate

import (
	"testing"

	"k8s.io/utils/ptr"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func TestCertificateSecretName(t *testing.T) {
	certWithSecretName := func(s string) *cmapi.Certificate {
		return &cmapi.Certificate{
			Spec: cmapi.CertificateSpec{SecretName: s},
		}
	}
	tests := map[string]struct {
		secretName string
		cert       *cmapi.Certificate
		expected   bool
	}{
		"returns true if secret name matches": {
			secretName: "abc",
			cert:       certWithSecretName("abc"),
			expected:   true,
		},
		"returns false if secret name does not match": {
			secretName: "abc",
			cert:       certWithSecretName("abcd"),
			expected:   false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := CertificateSecretName(test.secretName)(test.cert)
			if got != test.expected {
				t.Errorf("unexpected response: got=%t, exp=%t", got, test.expected)
			}
		})
	}
}

func TestCertificateNextPrivateKeySecretName(t *testing.T) {
	certWithSecretName := func(s *string) *cmapi.Certificate {
		return &cmapi.Certificate{
			Status: cmapi.CertificateStatus{NextPrivateKeySecretName: s},
		}
	}
	tests := map[string]struct {
		secretName string
		cert       *cmapi.Certificate
		expected   bool
	}{
		"returns true if secret name matches": {
			secretName: "abc",
			cert:       certWithSecretName(ptr.To("abc")),
			expected:   true,
		},
		"returns false if secret name does not match": {
			secretName: "abc",
			cert:       certWithSecretName(ptr.To("abcd")),
			expected:   false,
		},
		"returns false if secret name is nil": {
			secretName: "",
			cert:       certWithSecretName(nil),
			expected:   false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := CertificateNextPrivateKeySecretName(test.secretName)(test.cert)
			if got != test.expected {
				t.Errorf("unexpected response: got=%t, exp=%t", got, test.expected)
			}
		})
	}
}
