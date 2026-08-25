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

// This file originally mistakenly included the claim that it was copied from the robfig/cron project
// but it is entirely original work added by the cert-manager project

package cron

import "testing"

func TestParserParseReturnsErrorForTimezoneWithoutSchedule(t *testing.T) {
	parser := NewParser(Minute | Hour | Dom | Month | Dow)

	for _, spec := range []string{"TZ=UTC", "CRON_TZ=UTC"} {
		t.Run(spec, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse panicked for %q: %v", spec, r)
				}
			}()

			if _, err := parser.Parse(spec); err == nil {
				t.Fatalf("expected error for %q, got nil", spec)
			}
		})
	}
}
