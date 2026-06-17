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

package metrics

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	fakeclock "k8s.io/utils/clock/testing"

	acmemeta "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_clockTimeSeconds(t *testing.T) {
	fixedClock := fakeclock.NewFakeClock(time.Now())
	m := New(testr.New(t), fixedClock)

	tests := map[string]struct {
		metricName string
		metric     prometheus.Collector

		expected string
	}{
		"clock_time_seconds of type counter": {
			metricName: "certmanager_clock_time_seconds",
			metric:     m.clockTimeSeconds,
			expected: fmt.Sprintf(`
# HELP certmanager_clock_time_seconds DEPRECATED: use clock_time_seconds_gauge instead. The clock time given in seconds (from 1970/01/01 UTC).
# TYPE certmanager_clock_time_seconds counter
certmanager_clock_time_seconds %f
	`, float64(fixedClock.Now().Unix())),
		},
		"clock_time_seconds_gauge of type gauge": {
			metricName: "certmanager_clock_time_seconds_gauge",
			metric:     m.clockTimeSecondsGauge,
			expected: fmt.Sprintf(`
# HELP certmanager_clock_time_seconds_gauge The clock time given in seconds (from 1970/01/01 UTC). Gauge form of the deprecated clock_time_seconds counter. No labels.
# TYPE certmanager_clock_time_seconds_gauge gauge
certmanager_clock_time_seconds_gauge %f
	`, float64(fixedClock.Now().Unix())),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t,
				testutil.CollectAndCompare(test.metric, strings.NewReader(test.expected), test.metricName),
			)
		})
	}
}

func Test_ACMEChallenges(t *testing.T) {
	fixedClock := fakeclock.NewFakeClock(time.Now())
	m := New(testr.New(t), fixedClock)

	challenges := make([]*acmemeta.Challenge, 0)
	challenges = append(challenges, gen.Challenge("test-challenge-status",
		gen.SetChallengeDNSName("example.com"),
		gen.SetChallengeProcessing(false),
		gen.SetChallengeType(acmemeta.ACMEChallengeTypeDNS01),
		gen.SetChallengeState(acmemeta.Pending),
		gen.SetChallengeNamespace("test-challenge"),
	), gen.Challenge("test-challenge-status-1",
		gen.SetChallengeDNSName("example.com"),
		gen.SetChallengeProcessing(false),
		gen.SetChallengeType(acmemeta.ACMEChallengeTypeDNS01),
		gen.SetChallengeState(acmemeta.Ready),
		gen.SetChallengeNamespace("test-challenge"),
	))

	fakeClient := fake.NewClientset()
	factory := externalversions.NewSharedInformerFactory(fakeClient, 0)
	challengesInformer := factory.Acme().V1().Challenges()
	for _, ch := range challenges {
		err := challengesInformer.Informer().GetIndexer().Add(ch)
		assert.NoError(t, err)
	}

	m.SetupACMECollector(challengesInformer.Lister())

	tests := map[string]struct {
		metricName string
		metric     prometheus.Collector

		expected string
	}{
		"challenge_status": {
			metricName: "certmanager_certificate_challenge_status",
			metric:     m.challengeCollector,
			expected: `
# HELP certmanager_certificate_challenge_status The status of certificate challenges
# TYPE certmanager_certificate_challenge_status gauge
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status",namespace="test-challenge",processing="false",reason="",status="",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status",namespace="test-challenge",processing="false",reason="",status="errored",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status",namespace="test-challenge",processing="false",reason="",status="expired",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status",namespace="test-challenge",processing="false",reason="",status="invalid",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status",namespace="test-challenge",processing="false",reason="",status="pending",type="DNS-01"} 1
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status",namespace="test-challenge",processing="false",reason="",status="processing",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status",namespace="test-challenge",processing="false",reason="",status="ready",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status",namespace="test-challenge",processing="false",reason="",status="valid",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status-1",namespace="test-challenge",processing="false",reason="",status="",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status-1",namespace="test-challenge",processing="false",reason="",status="errored",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status-1",namespace="test-challenge",processing="false",reason="",status="expired",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status-1",namespace="test-challenge",processing="false",reason="",status="invalid",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status-1",namespace="test-challenge",processing="false",reason="",status="pending",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status-1",namespace="test-challenge",processing="false",reason="",status="processing",type="DNS-01"} 0
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status-1",namespace="test-challenge",processing="false",reason="",status="ready",type="DNS-01"} 1
certmanager_certificate_challenge_status{domain="example.com",name="test-challenge-status-1",namespace="test-challenge",processing="false",reason="",status="valid",type="DNS-01"} 0
	`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t,
				testutil.CollectAndCompare(test.metric, strings.NewReader(test.expected), test.metricName),
			)
		})
	}
}
