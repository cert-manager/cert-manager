// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"log"
	"reflect"
	"testing"

	"github.com/golang/dep/internal/test"
)

func TestSourceManager_InferConstraint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	t.Parallel()

	// Used in git subtests:
	v081, err := NewSemverConstraintIC("v0.8.1")
	if err != nil {
		t.Fatal(err)
	}
	v012, err := NewSemverConstraintIC("v0.12.0-12-de4dcafe0")
	if err != nil {
		t.Fatal(err)
	}

	// Used in hg and bzr subtests:
	v1, err := NewSemverConstraintIC("v1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	var (
		gitProj = ProjectIdentifier{ProjectRoot: "github.com/carolynvs/deptest"}
		bzrProj = ProjectIdentifier{ProjectRoot: "launchpad.net/govcstestbzrrepo"}
		hgProj  = ProjectIdentifier{ProjectRoot: "bitbucket.org/golang-dep/dep-test"}

		testcases = []struct {
			project ProjectIdentifier
			name    string
			str     string
			want    Constraint
		}{
			{gitProj, "empty", "", Any()},
			{gitProj, "semver-short", "v0.8.1", v081},
			{gitProj, "long semver constraint", "v0.12.0-12-de4dcafe0", v012},
			{gitProj, "branch v2", "v2", NewBranch("v2")},
			{gitProj, "branch master", "master", NewBranch("master")},
			{gitProj, "long revision", "3f4c3bea144e112a69bbe5d8d01c1b09a544253f",
				Revision("3f4c3bea144e112a69bbe5d8d01c1b09a544253f")},
			{gitProj, "short revision", "3f4c3bea",
				Revision("3f4c3bea144e112a69bbe5d8d01c1b09a544253f")},

			{bzrProj, "empty", "", Any()},
			{bzrProj, "semver", "v1.0.0", v1},
			{bzrProj, "revision", "matt@mattfarina.com-20150731135137-pbphasfppmygpl68",
				Revision("matt@mattfarina.com-20150731135137-pbphasfppmygpl68")},

			{hgProj, "empty", "", Any()},
			{hgProj, "semver", "v1.0.0", v1},
			{hgProj, "default branch", "default", NewBranch("default")},
			{hgProj, "revision", "6f55e1f03d91f8a7cce35d1968eb60a2352e4d59",
				Revision("6f55e1f03d91f8a7cce35d1968eb60a2352e4d59")},
			{hgProj, "short revision", "6f55e1f03d91",
				Revision("6f55e1f03d91f8a7cce35d1968eb60a2352e4d59")},
		}
	)

	for _, tc := range testcases {
		var subtestName string
		switch tc.project {
		case gitProj:
			subtestName = "git-" + tc.name
		case bzrProj:
			subtestName = "bzr-" + tc.name
		case hgProj:
			subtestName = "hg-" + tc.name
		default:
			subtestName = tc.name
		}

		t.Run(subtestName, func(t *testing.T) {
			t.Parallel()
			h := test.NewHelper(t)
			defer h.Cleanup()

			cacheDir := "gps-repocache"
			h.TempDir(cacheDir)

			sm, err := NewSourceManager(SourceManagerConfig{
				Cachedir: h.Path(cacheDir),
				Logger:   log.New(test.Writer{TB: t}, "", 0),
			})
			h.Must(err)

			got, err := sm.InferConstraint(tc.str, tc.project)
			h.Must(err)

			wantT := reflect.TypeOf(tc.want)
			gotT := reflect.TypeOf(got)
			if wantT != gotT {
				t.Errorf("expected type: %s, got %s, for input %s", wantT, gotT, tc.str)
			}
			if got.String() != tc.want.String() {
				t.Errorf("expected value: %s, got %s for input %s", tc.want, got, tc.str)
			}
		})
	}
}
