// +skip_license_check

/*
This file contains tests for portions of code directly taken from the
'robfig/cron' project. A copy of the license for this code can be found in
the file named LICENSE in this directory.
*/

package cron

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"
)

// fieldExpr is a generated cron field expression together with the set of
// values it should match, computed independently from the parser.
type fieldExpr struct {
	expr string
	set  map[int]bool
	star bool // true only for "*", which affects the day-of-month/week rule
}

func drawFieldExpr(tc hegel.TestCase, min, max int) fieldExpr {
	values := func(lo, hi, step int) map[int]bool {
		set := map[int]bool{}
		for v := lo; v <= hi; v += step {
			set[v] = true
		}
		return set
	}
	switch hegel.Draw(tc, hegel.Integers(0, 4)) {
	case 0:
		return fieldExpr{"*", values(min, max, 1), true}
	case 1: // list of 1-3 single values
		set := map[int]bool{}
		var parts []string
		for _, v := range hegel.Draw(tc, hegel.Lists(hegel.Integers(min, max)).MinSize(1).MaxSize(3)) {
			set[v] = true
			parts = append(parts, fmt.Sprint(v))
		}
		return fieldExpr{strings.Join(parts, ","), set, false}
	case 2: // range a-b
		a := hegel.Draw(tc, hegel.Integers(min, max))
		b := hegel.Draw(tc, hegel.Integers(a, max))
		return fieldExpr{fmt.Sprintf("%d-%d", a, b), values(a, b, 1), false}
	case 3: // */s: full range stepped; note this does NOT count as a star
		s := hegel.Draw(tc, hegel.Integers(2, max-min))
		return fieldExpr{fmt.Sprintf("*/%d", s), values(min, max, s), false}
	default: // a-b/s
		a := hegel.Draw(tc, hegel.Integers(min, max))
		b := hegel.Draw(tc, hegel.Integers(a, max))
		s := hegel.Draw(tc, hegel.Integers(1, max-min))
		return fieldExpr{fmt.Sprintf("%d-%d/%d", a, b, s), values(a, b, s), false}
	}
}

// TestSpecScheduleNextProperties generates cron expressions with known
// matching sets for each field and checks, in UTC and in a DST-observing
// timezone, that Next(t):
//
//   - is strictly after t, aligned to a whole minute
//   - matches the generated minute, hour and month sets, and the standard
//     cron day rule (dom AND dow when either is "*", dom OR dow otherwise)
//   - is a fixed point: Next(Next(t)-1s) == Next(t)
//   - is minimal: a drawn minute-aligned time strictly between t and Next(t)
//     never matches
//
// Next returning the zero time (no match within the parser's search horizon)
// is skipped: some generated day/month combinations are unsatisfiable.
func TestSpecScheduleNextProperties(t *testing.T) {
	parser := NewParser(Minute | Hour | Dom | Month | Dow)
	transitions := []int64{
		time.Date(2026, time.March, 8, 0, 0, 0, 0, time.UTC).Unix(),
		time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC).Unix(),
	}

	hegel.Test(t, func(ht *hegel.T) {
		minute := drawFieldExpr(ht, 0, 59)
		hour := drawFieldExpr(ht, 0, 23)
		dom := drawFieldExpr(ht, 1, 31)
		month := drawFieldExpr(ht, 1, 12)
		dow := drawFieldExpr(ht, 0, 6)
		tz := hegel.Draw(ht, hegel.SampledFrom([]string{"UTC", "America/Denver"}))

		spec := fmt.Sprintf("CRON_TZ=%s %s %s %s %s %s", tz, minute.expr, hour.expr, dom.expr, month.expr, dow.expr)
		sched, err := parser.Parse(spec)
		if err != nil {
			ht.Fatalf("failed to parse %q: %v", spec, err)
		}

		var start int64
		if hegel.Draw(ht, hegel.Booleans()) {
			start = hegel.Draw(ht, hegel.SampledFrom(transitions)) + hegel.Draw(ht, hegel.Integers[int64](-3*24*3600, 3*24*3600))
		} else {
			start = hegel.Draw(ht, hegel.Integers[int64](0, 4_000_000_000))
		}
		loc, err := time.LoadLocation(tz)
		if err != nil {
			ht.Fatalf("%v", err)
		}
		from := time.Unix(start, 0).In(loc)

		next := sched.Next(from)
		ht.Assume(!next.IsZero())

		matches := func(u time.Time) (bool, string) {
			if !minute.set[u.Minute()] {
				return false, fmt.Sprintf("minute %d not in %q", u.Minute(), minute.expr)
			}
			if !hour.set[u.Hour()] {
				return false, fmt.Sprintf("hour %d not in %q", u.Hour(), hour.expr)
			}
			if !month.set[int(u.Month())] {
				return false, fmt.Sprintf("month %d not in %q", u.Month(), month.expr)
			}
			domMatch, dowMatch := dom.set[u.Day()], dow.set[int(u.Weekday())]
			if dom.star || dow.star {
				if !(domMatch && dowMatch) {
					return false, fmt.Sprintf("day %d / weekday %d not in %q and %q", u.Day(), u.Weekday(), dom.expr, dow.expr)
				}
			} else if !(domMatch || dowMatch) {
				return false, fmt.Sprintf("day %d / weekday %d not in %q or %q", u.Day(), u.Weekday(), dom.expr, dow.expr)
			}
			return true, ""
		}

		if !next.After(from) {
			ht.Fatalf("%q: Next(%s) = %s is not after it", spec, from, next)
		}
		if next.Second() != 0 || next.Nanosecond() != 0 {
			ht.Fatalf("%q: Next(%s) = %s is not minute-aligned", spec, from, next)
		}
		if ok, why := matches(next.In(loc)); !ok {
			ht.Fatalf("%q: Next(%s) = %s does not match: %s", spec, from, next, why)
		}
		if again := sched.Next(next.Add(-time.Second)); !again.Equal(next) {
			ht.Fatalf("%q: Next(%s) = %s but Next(%s) = %s", spec, from, next, next.Add(-time.Second), again)
		}

		// Minimality spot check: a minute-aligned time strictly between from
		// and next must not match.
		gapMinutes := int64(next.Sub(from.Truncate(time.Minute)) / time.Minute)
		if gapMinutes > 1 {
			between := from.Truncate(time.Minute).Add(time.Duration(hegel.Draw(ht, hegel.Integers[int64](1, gapMinutes-1))) * time.Minute)
			if between.After(from) && between.Before(next) {
				if ok, _ := matches(between.In(loc)); ok {
					ht.Fatalf("%q: %s matches but Next(%s) skipped past it to %s", spec, between, from, next)
				}
			}
		}
	}, hegel.WithTestCases(1000))
}
