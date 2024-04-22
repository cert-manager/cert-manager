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

	logtesting "github.com/go-logr/logr/testing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	fakeclock "k8s.io/utils/clock/testing"
)

func Test_clockTimeSeconds(t *testing.T) {
	fixedClock := fakeclock.NewFakeClock(time.Now())
	m := New(logtesting.NewTestLogger(t), fixedClock)

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
# HELP certmanager_clock_time_seconds_gauge The clock time given in seconds (from 1970/01/01 UTC).
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
