/*
Copyright 2020 The cert-manager Authors.

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
	"fmt"
	"strings"
)

// TruncationMarker is appended to messages shortened by TruncateMessage so that
// readers can tell the message is incomplete.
const TruncationMarker = "... (truncated)"

type invalidDataError struct{ error }

func NewInvalidData(str string, obj ...any) error {
	return &invalidDataError{error: fmt.Errorf(str, obj...)}
}

func IsInvalidData(err error) bool {
	if _, ok := err.(*invalidDataError); !ok {
		return false
	}
	return true
}

// TruncateMessage bounds s to maxLen bytes in total, including the marker which
// is appended so that readers can tell the message is incomplete.
func TruncateMessage(s string, maxLen int) string {
	// Nothing fits within a non-positive bound. Guarding here also keeps a
	// negative bound from panicking on the slices below.
	if maxLen <= 0 {
		return ""
	}

	if len(s) <= maxLen {
		return s
	}

	// Cutting on a byte boundary can split a multi-byte rune in half. Replacing
	// invalid sequences keeps the result valid UTF-8, which the API server
	// requires of the strings it stores.
	if maxLen <= len(TruncationMarker) {
		return strings.ToValidUTF8(s[:maxLen], "")
	}

	truncated := strings.ToValidUTF8(s[:maxLen-len(TruncationMarker)], "")

	// Trim trailing whitespace so that the marker reads cleanly.
	return strings.TrimRight(truncated, " \t\r\n") + TruncationMarker
}
