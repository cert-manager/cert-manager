// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"testing"

	"github.com/Masterminds/vcs"
)

func TestUnwrapVcsErrNonNil(t *testing.T) {
	for _, err := range []error{
		vcs.NewRemoteError("msg", nil, "out"),
		vcs.NewRemoteError("msg", nil, ""),
		vcs.NewRemoteError("", nil, "out"),
		vcs.NewRemoteError("", nil, ""),
		vcs.NewLocalError("msg", nil, "out"),
		vcs.NewLocalError("msg", nil, ""),
		vcs.NewLocalError("", nil, "out"),
		vcs.NewLocalError("", nil, ""),
		&vcs.RemoteError{},
		&vcs.LocalError{},
	} {
		if unwrapVcsErr(err) == nil {
			t.Errorf("unexpected nil error unwrapping: %#v", err)
		}
	}
}
