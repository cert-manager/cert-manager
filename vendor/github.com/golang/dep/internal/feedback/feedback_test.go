// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package feedback

import (
	"bytes"
	log2 "log"
	"strings"
	"testing"

	"github.com/golang/dep/gps"
	_ "github.com/golang/dep/internal/test" // DO NOT REMOVE, allows go test ./... -update to work
)

func TestFeedback_Constraint(t *testing.T) {
	ver, _ := gps.NewSemverConstraint("^1.0.0")
	rev := gps.Revision("1b8edb3")
	pi := gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/foo/bar")}

	cases := []struct {
		feedback *ConstraintFeedback
		want     string
	}{
		{
			feedback: NewConstraintFeedback(gps.ProjectConstraint{Constraint: ver, Ident: pi}, DepTypeDirect),
			want:     "Using ^1.0.0 as constraint for direct dep github.com/foo/bar",
		},
		{
			feedback: NewConstraintFeedback(gps.ProjectConstraint{Constraint: ver, Ident: pi}, DepTypeImported),
			want:     "Using ^1.0.0 as initial constraint for imported dep github.com/foo/bar",
		},
		{
			feedback: NewConstraintFeedback(gps.ProjectConstraint{Constraint: gps.Any(), Ident: pi}, DepTypeImported),
			want:     "Using * as initial constraint for imported dep github.com/foo/bar",
		},
		{
			feedback: NewConstraintFeedback(gps.ProjectConstraint{Constraint: rev, Ident: pi}, DepTypeDirect),
			want:     "Using 1b8edb3 as hint for direct dep github.com/foo/bar",
		},
		{
			feedback: NewConstraintFeedback(gps.ProjectConstraint{Constraint: rev, Ident: pi}, DepTypeImported),
			want:     "Using 1b8edb3 as initial hint for imported dep github.com/foo/bar",
		},
	}

	for _, c := range cases {
		buf := &bytes.Buffer{}
		log := log2.New(buf, "", 0)
		c.feedback.LogFeedback(log)
		got := strings.TrimSpace(buf.String())
		if c.want != got {
			t.Errorf("Feedbacks are not expected: \n\t(GOT) '%s'\n\t(WNT) '%s'", got, c.want)
		}
	}
}

func TestFeedback_LockedProject(t *testing.T) {
	v := gps.NewVersion("v1.1.4").Pair("bc29b4f")
	b := gps.NewBranch("master").Pair("436f39d")
	pi := gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/foo/bar")}

	cases := []struct {
		feedback *ConstraintFeedback
		want     string
	}{
		{
			feedback: NewLockedProjectFeedback(gps.NewLockedProject(pi, v, nil), DepTypeDirect),
			want:     "Locking in v1.1.4 (bc29b4f) for direct dep github.com/foo/bar",
		},
		{
			feedback: NewLockedProjectFeedback(gps.NewLockedProject(pi, v, nil), DepTypeImported),
			want:     "Trying v1.1.4 (bc29b4f) as initial lock for imported dep github.com/foo/bar",
		},
		{
			feedback: NewLockedProjectFeedback(gps.NewLockedProject(pi, gps.NewVersion("").Pair("bc29b4f"), nil), DepTypeImported),
			want:     "Trying * (bc29b4f) as initial lock for imported dep github.com/foo/bar",
		},
		{
			feedback: NewLockedProjectFeedback(gps.NewLockedProject(pi, b, nil), DepTypeTransitive),
			want:     "Locking in master (436f39d) for transitive dep github.com/foo/bar",
		},
	}

	for _, c := range cases {
		buf := &bytes.Buffer{}
		log := log2.New(buf, "", 0)
		c.feedback.LogFeedback(log)
		got := strings.TrimSpace(buf.String())
		if c.want != got {
			t.Errorf("Feedbacks are not expected: \n\t(GOT) '%s'\n\t(WNT) '%s'", got, c.want)
		}
	}
}

func TestFeedback_BrokenImport(t *testing.T) {
	pi := gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/foo/bar")}

	cases := []struct {
		oldVersion     gps.Version
		currentVersion gps.Version
		pID            gps.ProjectIdentifier
		altPID         gps.ProjectIdentifier
		want           string
		name           string
	}{
		{
			oldVersion:     gps.NewVersion("v1.1.4").Pair("bc29b4f"),
			currentVersion: gps.NewVersion("v1.2.0").Pair("ia3da28"),
			pID:            pi,
			altPID:         pi,
			want:           "Warning: Unable to preserve imported lock v1.1.4 (bc29b4f) for github.com/foo/bar. Locking in v1.2.0 (ia3da28)",
			name:           "Basic broken import",
		},
		{
			oldVersion:     gps.NewBranch("master").Pair("bc29b4f"),
			currentVersion: gps.NewBranch("dev").Pair("ia3da28"),
			pID:            pi,
			altPID:         pi,
			want:           "Warning: Unable to preserve imported lock master (bc29b4f) for github.com/foo/bar. Locking in dev (ia3da28)",
			name:           "Branches",
		},
		{
			oldVersion:     gps.NewBranch("master").Pair("bc29b4f"),
			currentVersion: gps.NewBranch("dev").Pair("ia3da28"),
			pID:            pi,
			altPID:         gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/foo/boo")},
			want:           "Warning: Unable to preserve imported lock master (bc29b4f) for github.com/foo/bar. The project was removed from the lock because it is not used.",
			name:           "Branches",
		},
		{
			oldVersion:     gps.NewBranch("master").Pair("bc29b4f"),
			currentVersion: gps.NewBranch("dev").Pair("ia3da28"),
			pID:            gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/foo/boo"), Source: "github.com/das/foo"},
			altPID:         gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/foo/boo"), Source: "github.com/das/bar"},
			want:           "Warning: Unable to preserve imported lock master (bc29b4f) for github.com/foo/boo(github.com/das/foo). Locking in dev (ia3da28) for github.com/foo/boo(github.com/das/bar)",
			name:           "With a source",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			ol := gps.SimpleLock{
				gps.NewLockedProject(c.pID, c.oldVersion, nil),
			}
			l := gps.SimpleLock{
				gps.NewLockedProject(c.altPID, c.currentVersion, nil),
			}
			log := log2.New(buf, "", 0)
			feedback := NewBrokenImportFeedback(DiffLocks(&ol, &l))
			feedback.LogFeedback(log)
			got := strings.TrimSpace(buf.String())
			if c.want != got {
				t.Errorf("Feedbacks are not expected: \n\t(GOT) '%s'\n\t(WNT) '%s'", got, c.want)
			}
		})
	}
}
