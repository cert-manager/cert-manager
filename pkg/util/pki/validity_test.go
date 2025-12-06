/*
Copyright 2025 The cert-manager Authors.

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

package pki

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestCertificateNotAfterValidity(t *testing.T) {
	testCases := []struct {
		name      string
		template  *x509.Certificate
		caCerts   []*x509.Certificate
		expected  time.Time
		expectErr bool
	}{
		{
			name: "no CA certificates",
			template: &x509.Certificate{
				NotAfter: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			caCerts:   nil,
			expected:  time.Time{},
			expectErr: true,
		},
		{
			name: "CA certificate with earlier expiration",
			template: &x509.Certificate{
				NotAfter: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			caCerts: []*x509.Certificate{
				{
					NotAfter: time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC),
				},
			},
			expected:  time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC),
			expectErr: false,
		},
		{
			name: "CA certificate with later expiration",
			template: &x509.Certificate{
				NotAfter: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			caCerts: []*x509.Certificate{
				{
					NotAfter: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			expected:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			expectErr: false,
		},
		{
			name: "multiple CA certificates with different expirations",
			template: &x509.Certificate{
				NotAfter: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			caCerts: []*x509.Certificate{
				{
					NotAfter: time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC),
				},
				{
					NotAfter: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
				},
				{
					NotAfter: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
				},
			},
			expected:  time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC),
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CertificateNotAfterValidity(tc.template, tc.caCerts)
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !result.Equal(tc.expected) {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}

}
