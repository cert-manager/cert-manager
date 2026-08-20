/*
Copyright The cert-manager Authors.

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

package cron

import (
	"testing"
	"time"
)

func TestNextLeapDayAcrossNonLeapCentury(t *testing.T) {
	sched, err := ParseStandard("0 0 29 2 *")
	if err != nil {
		t.Fatal(err)
	}

	// 2100 is not a leap year, so the gap from 2096-02-29 to 2104-02-29 is 8 years.
	// A 5-year search horizon returns the zero time here.
	got := sched.Next(time.Date(2096, time.March, 1, 0, 0, 0, 0, time.UTC))
	want := time.Date(2104, time.February, 29, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("Next() = %v, want %v", got, want)
	}
}

func TestNextLeapDayCommonFourYearGap(t *testing.T) {
	sched, err := ParseStandard("0 0 29 2 *")
	if err != nil {
		t.Fatal(err)
	}

	got := sched.Next(time.Date(2024, time.March, 1, 0, 0, 0, 0, time.UTC))
	want := time.Date(2028, time.February, 29, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("Next() = %v, want %v", got, want)
	}
}

func TestNextImpossibleDateStillZero(t *testing.T) {
	sched, err := ParseStandard("0 0 31 2 *")
	if err != nil {
		t.Fatal(err)
	}

	got := sched.Next(time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC))
	if !got.IsZero() {
		t.Fatalf("Next() = %v, want zero time", got)
	}
}
