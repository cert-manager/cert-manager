// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package paths

import (
	"testing"

	_ "github.com/golang/dep/internal/test" // DO NOT REMOVE, allows go test ./... -update to work
)

func TestIsStandardImportPath(t *testing.T) {
	fix := []struct {
		ip string
		is bool
	}{
		{"appengine", true},
		{"net/http", true},
		{"github.com/anything", false},
		{"github.com", false},
		{"foo", true},
		{".", false},
	}

	for _, f := range fix {
		r := IsStandardImportPath(f.ip)
		if r != f.is {
			if r {
				t.Errorf("%s was marked stdlib but should not have been", f.ip)
			} else {
				t.Errorf("%s was not marked stdlib but should have been", f.ip)

			}
		}
	}
}
