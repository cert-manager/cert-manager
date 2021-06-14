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

	"github.com/prometheus/client_golang/prometheus/testutil"

	logtesting "github.com/jetstack/cert-manager/pkg/logs/testing"
)

func TestClockMetrics(t *testing.T) {
	type testT struct {
		expectedFmt string
	}
	tests := map[string]testT{
		"clock time seconds as expected": {
			expectedFmt: `
  # HELP certmanager_clock_time_seconds The clock time given in seconds (from 1970/01/01 UTC).
  # TYPE certmanager_clock_time_seconds counter
	certmanager_clock_time_seconds %f
	`,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			m := New(logtesting.TestLogger{T: t})

			if err := testutil.CollectAndCompare(m.clockTimeSeconds,
				strings.NewReader(fmt.Sprintf(test.expectedFmt, float64(time.Now().Unix()))),
				"certmanager_clock_time_seconds",
			); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}
		})
	}
}
