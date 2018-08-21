// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import "testing"

// basically a regression test
func TestPathPrefixOrEqual(t *testing.T) {
	if !isPathPrefixOrEqual("foo", "foo") {
		t.Error("Same path should return true")
	}

	if isPathPrefixOrEqual("foo", "fooer") {
		t.Error("foo is not a path-type prefix of fooer")
	}

	if !isPathPrefixOrEqual("foo", "foo/bar") {
		t.Error("foo is a path prefix of foo/bar")
	}

	if isPathPrefixOrEqual("foo", "foo/") {
		t.Error("special case - foo is not a path prefix of foo/")
	}
}
