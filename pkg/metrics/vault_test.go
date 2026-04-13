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
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fakeclock "k8s.io/utils/clock/testing"
)

func TestObserveVaultRequestDuration(t *testing.T) {
	tests := []struct {
		name             string
		apiCall          string
		duration         time.Duration
		observationCount int
		expectedSum      float64
	}{
		{
			name:             "single sign_certificate observation",
			apiCall:          "sign_certificate",
			duration:         100 * time.Millisecond,
			observationCount: 1,
			expectedSum:      0.1,
		},
		{
			name:             "multiple observations are summed",
			apiCall:          "sign_certificate",
			duration:         250 * time.Millisecond,
			observationCount: 3,
			expectedSum:      0.75,
		},
		{
			name:             "different api_call label is tracked separately",
			apiCall:          "list_secrets",
			duration:         50 * time.Millisecond,
			observationCount: 2,
			expectedSum:      0.1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(testr.New(t), fakeclock.NewFakeClock(time.Now()))

			for i := 0; i < tt.observationCount; i++ {
				m.ObserveVaultRequestDuration(tt.duration, tt.apiCall)
			}

			obs, err := m.vaultClientRequestDurationSeconds.GetMetricWithLabelValues(tt.apiCall)
			require.NoError(t, err)

			pb := &dto.Metric{}
			require.NoError(t, obs.(interface {
				Write(*dto.Metric) error
			}).Write(pb))

			require.NotNil(t, pb.Summary)
			assert.Equal(t, uint64(tt.observationCount), pb.Summary.GetSampleCount(),
				"expected %d observations for api_call=%q", tt.observationCount, tt.apiCall)
			assert.InDelta(t, tt.expectedSum, pb.Summary.GetSampleSum(), 0.001,
				"expected sum=%v for api_call=%q", tt.expectedSum, tt.apiCall)
		})
	}
}
