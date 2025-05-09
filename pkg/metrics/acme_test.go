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
				gen.SetChallengeState(cmacme.Ready),
			),
			expectedMetric: `
			certmanager_certificate_challenge_status{domain="example.com",processing="false",reason="",status="ready"} 1
			`,
		},
	}

	for testName, test := range testCases {
		t.Run(testName, func(t *testing.T) {
			m := New(testr.New(t), clock.RealClock{})
			m.UpdateChallengeStatus(test.challenge)

			if err := testutil.CollectAndCompare(m.certificateChallenegeStatus,
				strings.NewReader(certificateChallengeStatusMetadata+test.expectedMetric),
				"certmanager_certificate_challenge_status",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}
		})
	}
}
