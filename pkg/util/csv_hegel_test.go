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

package util

import (
	"reflect"
	"strings"
	"testing"

	"hegel.dev/go/hegel"
)

// TestJoinSplitEscapeCSVRoundTrip checks that joining any list of strings to
// escaped CSV and splitting it again returns the original list. This is the
// production round trip between Certificate subject fields written to Secret
// annotations (JoinWithEscapeCSV) and ingress-shim annotations parsed into
// Certificate subject fields (SplitWithEscapeCSV).
//
// Two known counterexample classes are excluded below until fixed:
//
//   - [""]: joins to the empty string, which SplitWithEscapeCSV rejects
//     with "no values found".
//   - values containing "\r": encoding/csv's reader silently normalizes
//     "\r\n" to "\n" inside quoted fields, so the value comes back changed.
func TestJoinSplitEscapeCSVRoundTrip(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		xs := hegel.Draw(ht, hegel.Lists(hegel.Text().MaxSize(20)).MinSize(1).MaxSize(5))
		ht.Assume(!(len(xs) == 1 && xs[0] == ""))
		for _, x := range xs {
			ht.Assume(!strings.Contains(x, "\r"))
		}
		s, err := JoinWithEscapeCSV(xs)
		if err != nil {
			ht.Fatalf("join %q: %v", xs, err)
		}
		ys, err := SplitWithEscapeCSV(s)
		if err != nil {
			ht.Fatalf("split %q (from %q): %v", s, xs, err)
		}
		if !reflect.DeepEqual(xs, ys) {
			ht.Fatalf("round trip changed %q -> %q -> %q", xs, s, ys)
		}
	}, hegel.WithTestCases(2000))
}
