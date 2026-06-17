// +skip_license_check

/*
This file contains portions of code directly taken from the 'robfig/cron' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

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
