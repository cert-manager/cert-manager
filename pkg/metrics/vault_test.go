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

package metrics

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	fakeclock "k8s.io/utils/clock/testing"
)

func TestObserveVaultRequestDuration(t *testing.T) {
	testCases := []struct {
		name              string
		apiCall           string
		duration          time.Duration
		observationCount  int
		expectedHelp      string
		expectedType      string
		expectedSampleSum float64
	}{
		{
			name:              "Single sign_certificate request",
			apiCall:           "sign_certificate",
			duration:          100 * time.Millisecond,
			observationCount:  1,
			expectedHelp:      "ALPHA: The Vault API request latencies in seconds for the Certificate Manager client. This metric is currently alpha as we would like to understand whether it helps to measure Certificate Manager call latency. Please leave feedback if you have any.",
			expectedType:      "summary",
			expectedSampleSum: 0.1,
		},
		{
			name:              "Multiple issue_certificate requests",
			apiCall:           "issue_certificate",
			duration:          250 * time.Millisecond,
			observationCount:  3,
			expectedHelp:      "ALPHA: The Vault API request latencies in seconds for the Certificate Manager client. This metric is currently alpha as we would like to understand whether it helps to measure Certificate Manager call latency. Please leave feedback if you have any.",
			expectedType:      "summary",
			expectedSampleSum: 0.75, // 3 requests * 0.25 seconds
		},
		{
			name:              "Long duration read_ca request",
			apiCall:           "read_ca",
			duration:          2 * time.Second,
			observationCount:  1,
			expectedHelp:      "ALPHA: The Vault API request latencies in seconds for the Certificate Manager client. This metric is currently alpha as we would like to understand whether it helps to measure Certificate Manager call latency. Please leave feedback if you have any.",
			expectedType:      "summary",
			expectedSampleSum: 2.0,
		},
		{
			name:              "Fast configure_ca request",
			apiCall:           "configure_ca",
			duration:          10 * time.Millisecond,
			observationCount:  1,
			expectedHelp:      "ALPHA: The Vault API request latencies in seconds for the Certificate Manager client. This metric is currently alpha as we would like to understand whether it helps to measure Certificate Manager call latency. Please leave feedback if you have any.",
			expectedType:      "summary",
			expectedSampleSum: 0.01,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fixedClock := fakeclock.NewFakeClock(time.Now())
			metrics := New(testr.New(t), fixedClock)

			// Observe the metric multiple times if specified
			for i := 0; i < tc.observationCount; i++ {
				metrics.ObserveVaultRequestDuration(tc.duration, tc.apiCall)
			}

			// Construct expected metric output
			expectedMetric := fmt.Sprintf(`
				# HELP certmanager_http_vault_client_request_duration_seconds %s
				# TYPE certmanager_http_vault_client_request_duration_seconds %s
				certmanager_http_vault_client_request_duration_seconds{api_call="%s",quantile="0.5"} %g
				certmanager_http_vault_client_request_duration_seconds{api_call="%s",quantile="0.9"} %g
				certmanager_http_vault_client_request_duration_seconds{api_call="%s",quantile="0.99"} %g
				certmanager_http_vault_client_request_duration_seconds_sum{api_call="%s"} %g
				certmanager_http_vault_client_request_duration_seconds_count{api_call="%s"} %d
				`,
				tc.expectedHelp,
				tc.expectedType,
				tc.apiCall, tc.duration.Seconds(),
				tc.apiCall, tc.duration.Seconds(),
				tc.apiCall, tc.duration.Seconds(),
				tc.apiCall, tc.expectedSampleSum,
				tc.apiCall, tc.observationCount,
			)

			err := testutil.CollectAndCompare(
				metrics.vaultClientRequestDurationSeconds,
				strings.NewReader(expectedMetric),
				"certmanager_http_vault_client_request_duration_seconds",
			)
			if err != nil {
				t.Errorf("unexpected metric result:\n%v", err)
			}
		})
	}
}

func TestObserveVaultRequestDuration_MultipleAPICallsIndependent(t *testing.T) {
	fixedClock := fakeclock.NewFakeClock(time.Now())
	metrics := New(testr.New(t), fixedClock)

	// Observe different API calls with different durations
	metrics.ObserveVaultRequestDuration(100*time.Millisecond, "sign_certificate")
	metrics.ObserveVaultRequestDuration(200*time.Millisecond, "issue_certificate")
	metrics.ObserveVaultRequestDuration(150*time.Millisecond, "sign_certificate")

	// Expected output should have both API calls tracked independently
	expectedMetric := `
		# HELP certmanager_http_vault_client_request_duration_seconds ALPHA: The Vault API request latencies in seconds for the Certificate Manager client. This metric is currently alpha as we would like to understand whether it helps to measure Certificate Manager call latency. Please leave feedback if you have any.
		# TYPE certmanager_http_vault_client_request_duration_seconds summary
		certmanager_http_vault_client_request_duration_seconds{api_call="issue_certificate",quantile="0.5"} 0.2
		certmanager_http_vault_client_request_duration_seconds{api_call="issue_certificate",quantile="0.9"} 0.2
		certmanager_http_vault_client_request_duration_seconds{api_call="issue_certificate",quantile="0.99"} 0.2
		certmanager_http_vault_client_request_duration_seconds_sum{api_call="issue_certificate"} 0.2
		certmanager_http_vault_client_request_duration_seconds_count{api_call="issue_certificate"} 1
		certmanager_http_vault_client_request_duration_seconds{api_call="sign_certificate",quantile="0.5"} 0.1
		certmanager_http_vault_client_request_duration_seconds{api_call="sign_certificate",quantile="0.9"} 0.15
		certmanager_http_vault_client_request_duration_seconds{api_call="sign_certificate",quantile="0.99"} 0.15
		certmanager_http_vault_client_request_duration_seconds_sum{api_call="sign_certificate"} 0.25
		certmanager_http_vault_client_request_duration_seconds_count{api_call="sign_certificate"} 2
	`

	err := testutil.CollectAndCompare(
		metrics.vaultClientRequestDurationSeconds,
		strings.NewReader(expectedMetric),
		"certmanager_http_vault_client_request_duration_seconds",
	)
	assert.NoError(t, err, "multiple independent API calls should be tracked separately")
}

func TestObserveVaultRequestDuration_ZeroDuration(t *testing.T) {
	fixedClock := fakeclock.NewFakeClock(time.Now())
	metrics := New(testr.New(t), fixedClock)

	// Observe with zero duration (edge case)
	metrics.ObserveVaultRequestDuration(0, "health_check")

	expectedMetric := `
		# HELP certmanager_http_vault_client_request_duration_seconds ALPHA: The Vault API request latencies in seconds for the Certificate Manager client. This metric is currently alpha as we would like to understand whether it helps to measure Certificate Manager call latency. Please leave feedback if you have any.
		# TYPE certmanager_http_vault_client_request_duration_seconds summary
		certmanager_http_vault_client_request_duration_seconds{api_call="health_check",quantile="0.5"} 0
		certmanager_http_vault_client_request_duration_seconds{api_call="health_check",quantile="0.9"} 0
		certmanager_http_vault_client_request_duration_seconds{api_call="health_check",quantile="0.99"} 0
		certmanager_http_vault_client_request_duration_seconds_sum{api_call="health_check"} 0
		certmanager_http_vault_client_request_duration_seconds_count{api_call="health_check"} 1
	`

	err := testutil.CollectAndCompare(
		metrics.vaultClientRequestDurationSeconds,
		strings.NewReader(expectedMetric),
		"certmanager_http_vault_client_request_duration_seconds",
	)
	assert.NoError(t, err, "zero duration should be handled correctly")
}

func TestObserveVaultRequestDuration_HighPrecision(t *testing.T) {
	fixedClock := fakeclock.NewFakeClock(time.Now())
	metrics := New(testr.New(t), fixedClock)

	// Observe with microsecond precision
	metrics.ObserveVaultRequestDuration(1234*time.Microsecond, "quick_operation")

	expectedMetric := `
		# HELP certmanager_http_vault_client_request_duration_seconds ALPHA: The Vault API request latencies in seconds for the Certificate Manager client. This metric is currently alpha as we would like to understand whether it helps to measure Certificate Manager call latency. Please leave feedback if you have any.
		# TYPE certmanager_http_vault_client_request_duration_seconds summary
		certmanager_http_vault_client_request_duration_seconds{api_call="quick_operation",quantile="0.5"} 0.001234
		certmanager_http_vault_client_request_duration_seconds{api_call="quick_operation",quantile="0.9"} 0.001234
		certmanager_http_vault_client_request_duration_seconds{api_call="quick_operation",quantile="0.99"} 0.001234
		certmanager_http_vault_client_request_duration_seconds_sum{api_call="quick_operation"} 0.001234
		certmanager_http_vault_client_request_duration_seconds_count{api_call="quick_operation"} 1
	`

	err := testutil.CollectAndCompare(
		metrics.vaultClientRequestDurationSeconds,
		strings.NewReader(expectedMetric),
		"certmanager_http_vault_client_request_duration_seconds",
	)
	assert.NoError(t, err, "high precision durations should be tracked accurately")
}
