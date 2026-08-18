// +skip_license_check

/*
This file contains portions of code directly taken from the 'robfig/cron' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
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
