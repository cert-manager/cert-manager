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

package errors

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateMessage(t *testing.T) {
	tests := map[string]struct {
		in     string
		maxLen int
		want   string
	}{
		// maxLen is a bound on the whole result, so a limit of 20 leaves 5 bytes
		// for the message once the 15 byte marker has been accounted for.
		"a message within the limit is returned unchanged": {
			in:     "short",
			maxLen: 20,
			want:   "short",
		},
		"a message at the limit is returned unchanged": {
			in:     "exactly20bytes!!!!!!",
			maxLen: 20,
			want:   "exactly20bytes!!!!!!",
		},
		"a longer message is truncated": {
			in:     "abcdefghijklmnopqrstuvwxyz",
			maxLen: 20,
			want:   "abcde" + TruncationMarker,
		},
		"trailing whitespace is trimmed before the marker is added": {
			in:     "abc  defghijklmnopqrstuvwxyz",
			maxLen: 20,
			want:   "abc" + TruncationMarker,
		},
		"a multi-byte rune is not split in half": {
			// Each £ is two bytes, so the 5 byte budget falls in the middle of
			// the third one.
			in:     strings.Repeat("£", 12),
			maxLen: 20,
			want:   "££" + TruncationMarker,
		},
		"an invalid byte sequence is dropped": {
			in:     "ab\xffcdefghijklmnopqrstuvwxyz",
			maxLen: 20,
			want:   "abcd" + TruncationMarker,
		},
		"a limit too small for the marker drops the marker": {
			in:     "abcdefghij",
			maxLen: 4,
			want:   "abcd",
		},
		"a limit too small for the marker still respects rune boundaries": {
			in:     strings.Repeat("£", 4),
			maxLen: 3,
			want:   "£",
		},
		"a zero limit keeps nothing": {
			in:     "abcdefghij",
			maxLen: 0,
			want:   "",
		},
		// No caller passes a negative bound today, but this is a shared helper
		// and slicing by one would panic.
		"a negative limit keeps nothing": {
			in:     "abcdefghij",
			maxLen: -1,
			want:   "",
		},
		"a negative limit keeps nothing when there is nothing to keep": {
			in:     "",
			maxLen: -1,
			want:   "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := TruncateMessage(test.in, test.maxLen)
			if got != test.want {
				t.Errorf("TruncateMessage() = %q, want %q", got, test.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("TruncateMessage() = %q, which is not valid UTF-8", got)
			}
			// maxLen bounds the result in full, marker included.
			if want := max(test.maxLen, 0); len(got) > want {
				t.Errorf("TruncateMessage() returned %d bytes, want at most %d", len(got), want)
			}
		})
	}
}
