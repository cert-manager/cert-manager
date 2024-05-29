/*
Copyright 2021 The cert-manager Authors.

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

package v1alpha1

import (
	"encoding/json"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Duration is present for backwards compatibility for fields that
// previously used time.Duration.
// +k8s:conversion-gen=false
// +kubebuilder:validation:XIntOrString
type Duration struct {
	// Duration holds the duration
	Duration metav1.Duration
}

func DurationFromMetav1(d metav1.Duration) *Duration {
	return &Duration{Duration: d}
}

func DurationFromTime(d time.Duration) *Duration {
	return DurationFromMetav1(metav1.Duration{Duration: d})
}

func (t *Duration) MarshalJSON() ([]byte, error) {
	return t.Duration.MarshalJSON()
}

func (t *Duration) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		// string values unmarshal as metav1.Duration
		return json.Unmarshal(b, &t.Duration)
	}
	if err := json.Unmarshal(b, &t.Duration.Duration); err != nil {
		return fmt.Errorf("invalid duration %q: %w", string(b), err)
	}
	return nil
}

func (t *Duration) IsZero() bool {
	if t == nil {
		return true
	}

	return t.Duration.Duration == 0
}
