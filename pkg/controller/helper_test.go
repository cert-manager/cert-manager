/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package controller

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func TestCalculateDurationUntilRenew(t *testing.T) {
	c := IssuerOptions{
		RenewBeforeExpiryDuration: v1alpha1.DefaultRenewBefore,
	}
	currentTime := time.Now()
	now = func() time.Time { return currentTime }
	defer func() { now = time.Now }()
	tests := []struct {
		desc           string
		notBefore      time.Time
		notAfter       time.Time
		duration       *metav1.Duration
		renewBefore    *metav1.Duration
		expectedExpiry time.Duration
	}{
		{
			desc:           "generate an event if certificate duration is lower than requested duration",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour * 24 * 90),
			duration:       &metav1.Duration{time.Hour * 24 * 120},
			renewBefore:    nil,
			expectedExpiry: time.Hour * 24 * 60,
		},
		{
			desc:           "default expiry to 30 days",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour * 24 * 120),
			duration:       nil,
			renewBefore:    nil,
			expectedExpiry: (time.Hour * 24 * 120) - (time.Hour * 24 * 30),
		},
		{
			desc:           "default expiry to 2/3 of total duration if duration < 30 days",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour * 24 * 20),
			duration:       nil,
			renewBefore:    nil,
			expectedExpiry: time.Hour * 24 * 20 * 2 / 3,
		},
		{
			desc:           "expiry of 2/3 of certificate duration when duration < 30 minutes",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour),
			duration:       &metav1.Duration{time.Hour},
			renewBefore:    &metav1.Duration{time.Hour / 3},
			expectedExpiry: time.Hour * 2 / 3,
		},
		{
			desc:           "expiry of 60 days of certificate duration",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour * 24 * 365),
			duration:       &metav1.Duration{time.Hour * 24 * 365},
			renewBefore:    &metav1.Duration{time.Hour * 24 * 60},
			expectedExpiry: (time.Hour * 24 * 365) - (time.Hour * 24 * 60),
		},
		{
			desc:           "expiry of 2/3 of certificate duration when renewBefore greater than certificate duration",
			notBefore:      now(),
			notAfter:       now().Add(time.Hour * 24 * 35),
			duration:       &metav1.Duration{time.Hour * 24 * 35},
			renewBefore:    &metav1.Duration{time.Hour * 24 * 40},
			expectedExpiry: time.Hour * 24 * 35 * 2 / 3,
		},
		{
			// the notBefore of an LE certificate is one hour before issuance
			desc:           "expiry of let's encrypt certificate",
			notBefore:      now().Add(-time.Hour),
			notAfter:       now().Add(-time.Hour).Add(time.Hour * 24 * 90),
			duration:       nil,
			renewBefore:    &metav1.Duration{time.Hour*2159 + time.Minute*50},
			expectedExpiry: -time.Minute * 50,
		},
	}
	for k, v := range tests {
		cert := &v1alpha1.Certificate{
			Spec: v1alpha1.CertificateSpec{
				Duration:    v.duration,
				RenewBefore: v.renewBefore,
			},
		}
		x509Cert := &x509.Certificate{NotBefore: v.notBefore, NotAfter: v.notAfter}
		duration := c.CalculateDurationUntilRenew(context.Background(), x509Cert, cert)
		if duration != v.expectedExpiry {
			t.Errorf("test # %d - %s: got %v, expected %v", k, v.desc, duration, v.expectedExpiry)
		}
	}
}
