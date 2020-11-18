/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package v1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

func TestSetDefaultsCertificateSpec(t *testing.T) {
	t.Run("nil spec", func(t *testing.T) {
		SetDefaults_CertificateSpec(nil)
	})
}

func TestSetDefaultRenewBefore(t *testing.T) {
	type testCase struct {
		spec     *cmapi.CertificateSpec
		expected time.Duration
	}
	tests := map[string]testCase{
		"renew before already set": {
			spec: &cmapi.CertificateSpec{
				RenewBefore: &metav1.Duration{Duration: time.Hour * 123},
			},
			expected: time.Hour * 123,
		},
		"missing duration use default": {
			spec:     &cmapi.CertificateSpec{},
			expected: cmapi.DefaultRenewBefore,
		},
		"calculate renewBefore from  1/3 duration": {
			spec: &cmapi.CertificateSpec{
				Duration: &metav1.Duration{Duration: time.Hour * 3},
			},
			expected: time.Hour,
		},
		"Enforce minimum renewBefore": {
			spec: &cmapi.CertificateSpec{
				Duration: &metav1.Duration{Duration: time.Minute * 3},
			},
			expected: cmapi.MinimumRenewBefore,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {

			SetDefaults_CertificateSpec(tc.spec)

			assert.Equal(t, tc.expected, tc.spec.RenewBefore.Duration)
		})
	}
}
