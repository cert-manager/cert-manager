/*
Copyright 2025 The cert-manager Authors.

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

package collectors

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeChallengeReason(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", maxChallengeReasonLabelLen+100)
	got := normalizeChallengeReason(long)
	if len(got) != maxChallengeReasonLabelLen {
		t.Fatalf("expected length %d, got %d", maxChallengeReasonLabelLen, len(got))
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncated string is not valid UTF-8")
	}

	withNewlines := "before\nafter\r\n\tand\x00ctrl"
	got = normalizeChallengeReason(withNewlines)
	if strings.ContainsAny(got, "\n\r\t") {
		t.Fatalf("expected newlines replaced: %q", got)
	}
	if strings.ContainsRune(got, '\x00') {
		t.Fatal("expected control chars removed")
	}
}

func TestNormalizeChallengeReason_UTF8ByteBudget(t *testing.T) {
	t.Parallel()
	// Four-byte rune must not be written if it would exceed the byte cap mid-rune.
	prefix := strings.Repeat("a", maxChallengeReasonLabelLen-1)
	got := normalizeChallengeReason(prefix + "😀")
	if len(got) != maxChallengeReasonLabelLen-1 {
		t.Fatalf("expected emoji dropped to stay under byte cap: got len %d %q", len(got), got)
	}
	if !utf8.ValidString(got) {
		t.Fatal("output must be valid UTF-8")
	}
}

func TestNormalizeChallengeReason_UTF8ByteBudget_FitsExactRune(t *testing.T) {
	t.Parallel()

	prefix := strings.Repeat("a", maxChallengeReasonLabelLen-4)
	got := normalizeChallengeReason(prefix + "😀")

	if len(got) != maxChallengeReasonLabelLen {
		t.Fatalf("expected exact byte-budget fit, got len %d %q", len(got), got)
	}
	if !strings.HasSuffix(got, "😀") {
		t.Fatalf("expected emoji to fit exactly: %q", got)
	}
}
