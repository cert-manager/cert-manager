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
	"strings"
	"testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/utils/clock"
)

const certificateChallengeStatusMetadata = `
	# HELP certmanager_certificate_challenge_status The status of certificate challenges.
	# TYPE certmanager_certificate_challenge_status gauge
`

func TestCertificateChallengeStatusMetrics(t *testing.T) {
	type TestChallenge struct {
		challenge      *cmacme.Challenge
		expectedMetric string
	}

	testCases := map[string]TestChallenge{
		"challenge-metric-active-state-valid": {
			challenge: gen.Challenge("test-challenge-status",
				gen.SetChallengeDNSName("example.com"),
				gen.SetChallengeProcessing(false),
				gen.SetChallengeType(cmacme.ACMEChallengeTypeDNS01),
				gen.SetChallengeState(cmacme.Ready),
				gen.SetChallengeUID("test-challenge-uid"),
			),
			expectedMetric: `
			certmanager_certificate_challenge_status{domain="example.com",id="test-challenge-uid",processing="false",reason="",status="ready",type="DNS-01"} 1
			`,
		},
	}

	for testName, test := range testCases {
		t.Run(testName, func(t *testing.T) {
			m := New(testr.New(t), clock.RealClock{})
			m.UpdateChallengeStatus(test.challenge)

			if err := testutil.CollectAndCompare(m.certificateChallengeStatus,
				strings.NewReader(certificateChallengeStatusMetadata+test.expectedMetric),
				"certmanager_certificate_challenge_status",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}
		})
	}
}
