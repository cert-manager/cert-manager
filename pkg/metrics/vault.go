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
	"time"
)

// ObserveVaultRequestDuration records the duration of an outbound Vault API
// call. The api_call label identifies the logical operation (e.g.
// "sign_certificate").
func (m *Metrics) ObserveVaultRequestDuration(duration time.Duration, labels ...string) {
	m.vaultClientRequestDurationSeconds.WithLabelValues(labels...).Observe(duration.Seconds())
}
