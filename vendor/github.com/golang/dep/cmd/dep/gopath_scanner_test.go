// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"log"
	"reflect"
	"testing"

	"github.com/golang/dep"
	"github.com/golang/dep/gps"
	"github.com/golang/dep/internal/test"
)

const testProject1 = "github.com/sdboyer/deptest"
const testProject2 = "github.com/sdboyer/deptestdos"

// NewTestContext creates a unique context with its own GOPATH for a single test.
func NewTestContext(h *test.Helper) *dep.Ctx {
	h.TempDir("src")
	pwd := h.Path(".")
	discardLogger := log.New(ioutil.Discard, "", 0)

	return &dep.Ctx{
		GOPATH: pwd,
		Out:    discardLogger,
		Err:    discardLogger,
	}
}

func TestGopathScanner_OverlayManifestConstraints(t *testing.T) {
	h := test.NewHelper(t)
	h.Parallel()
	defer h.Cleanup()

	ctx := NewTestContext(h)

	pi1 := gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot(testProject1)}
	pi2 := gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot(testProject2)}
	v1 := gps.NewVersion("v1.0.0")
	v2 := gps.NewVersion("v2.0.0")
	v3 := gps.NewVersion("v3.0.0")
	rootM := dep.NewManifest()
	rootM.Constraints[pi1.ProjectRoot] = gps.ProjectProperties{Constraint: v1}
	rootL := &dep.Lock{}
	origM := dep.NewManifest()
	origM.Constraints[pi1.ProjectRoot] = gps.ProjectProperties{Constraint: v2}
	origM.Constraints[pi2.ProjectRoot] = gps.ProjectProperties{Constraint: v3}
	gs := gopathScanner{
		origM: origM,
		origL: &dep.Lock{},
		ctx:   ctx,
		pd: projectData{
			ondisk: map[gps.ProjectRoot]gps.Version{
				pi1.ProjectRoot: v2,
				pi2.ProjectRoot: v3,
			},
		},
	}

	gs.overlay(rootM, rootL)

	dep, has := rootM.Constraints[pi1.ProjectRoot]
	if !has {
		t.Fatalf("Expected the root manifest to contain %s", pi1.ProjectRoot)
	}
	wantC := v1.String()
	gotC := dep.Constraint.String()
	if wantC != gotC {
		t.Fatalf("Expected %s to be constrained to '%s', got '%s'", pi1.ProjectRoot, wantC, gotC)
	}

	dep, has = rootM.Constraints[pi2.ProjectRoot]
	if !has {
		t.Fatalf("Expected the root manifest to contain %s", pi2.ProjectRoot)
	}
	wantC = v3.String()
	gotC = dep.Constraint.String()
	if wantC != gotC {
		t.Fatalf("Expected %s to be constrained to '%s', got '%s'", pi2.ProjectRoot, wantC, gotC)
	}
}

func TestGopathScanner_OverlayLockProjects(t *testing.T) {
	h := test.NewHelper(t)
	h.Parallel()
	defer h.Cleanup()

	ctx := NewTestContext(h)

	rootM := dep.NewManifest()
	pi1 := gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot(testProject1)}
	pi2 := gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot(testProject2)}
	v1 := gps.NewVersion("v1.0.0")
	v2 := gps.NewVersion("v2.0.0")
	v3 := gps.NewVersion("v3.0.0")
	rootL := &dep.Lock{
		P: []gps.LockedProject{gps.NewLockedProject(pi1, v1, []string{})},
	}
	gs := gopathScanner{
		origM: dep.NewManifest(),
		origL: &dep.Lock{
			P: []gps.LockedProject{
				gps.NewLockedProject(pi1, v2, []string{}), // ignored, already exists in lock
				gps.NewLockedProject(pi2, v3, []string{}), // should be added to the lock
			},
		},
		ctx: ctx,
		pd: projectData{
			ondisk: map[gps.ProjectRoot]gps.Version{
				pi1.ProjectRoot: v2,
				pi2.ProjectRoot: v3,
			},
		},
	}

	gs.overlay(rootM, rootL)

	if len(rootL.P) != 2 {
		t.Fatalf("Expected the root manifest to contain 2 packages, got %d", len(rootL.P))
	}

	if rootL.P[0].Version() != v1 {
		t.Fatalf("Expected %s to be locked to '%s', got '%s'", rootL.P[0].Ident().ProjectRoot, v1, rootL.P[0].Version())
	}

	if rootL.P[1].Version() != v3 {
		t.Fatalf("Expected %s to be locked to '%s', got '%s'", rootL.P[1].Ident().ProjectRoot, v3, rootL.P[1].Version())
	}
}

func TestContains(t *testing.T) {
	t.Parallel()
	a := []string{"a", "b", "abcd"}

	if !contains(a, "a") {
		t.Fatal("expected array to contain 'a'")
	}
	if contains(a, "d") {
		t.Fatal("expected array to not contain 'd'")
	}
}

func TestGetProjectPropertiesFromVersion(t *testing.T) {
	t.Parallel()
	wantSemver, _ := gps.NewSemverConstraintIC("v1.0.0")
	cases := []struct {
		version, want gps.Constraint
	}{
		{
			version: gps.NewBranch("foo-branch"),
			want:    gps.NewBranch("foo-branch"),
		},
		{
			version: gps.NewVersion("foo-version"),
			want:    gps.NewVersion("foo-version"),
		},
		{
			version: gps.NewVersion("v1.0.0"),
			want:    wantSemver,
		},
		{
			version: gps.NewBranch("foo-branch").Pair("some-revision"),
			want:    gps.NewBranch("foo-branch"),
		},
		{
			version: gps.NewVersion("foo-version").Pair("some-revision"),
			want:    gps.NewVersion("foo-version"),
		},
		{
			version: gps.Revision("some-revision"),
			want:    nil,
		},
		{
			version: gps.NewVersion("v1.0.0").Pair("some-revision"),
			want:    wantSemver,
		},
	}

	for _, c := range cases {
		actualProp := getProjectPropertiesFromVersion(c.version.(gps.Version))
		if !reflect.DeepEqual(c.want, actualProp.Constraint) {
			t.Fatalf("Constraints are not as expected: \n\t(GOT) %v\n\t(WNT) %v", actualProp.Constraint, c.want)
		}
	}
}
