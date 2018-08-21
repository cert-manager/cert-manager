// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package feedback

import (
	"bytes"
	"testing"

	"github.com/golang/dep/gps"
)

// mkPI creates a ProjectIdentifier with the ProjectRoot as the provided
// string, and the Source unset.
//
// Call normalize() on the returned value if you need the Source to be be
// equal to the ProjectRoot.
func mkPI(root string) gps.ProjectIdentifier {
	return gps.ProjectIdentifier{
		ProjectRoot: gps.ProjectRoot(root),
	}
}

func TestStringDiff_NoChange(t *testing.T) {
	diff := StringDiff{Previous: "foo", Current: "foo"}
	want := "foo"
	got := diff.String()
	if got != want {
		t.Fatalf("Expected '%s', got '%s'", want, got)
	}
}

func TestStringDiff_Add(t *testing.T) {
	diff := StringDiff{Current: "foo"}
	got := diff.String()
	if got != "+ foo" {
		t.Fatalf("Expected '+ foo', got '%s'", got)
	}
}

func TestStringDiff_Remove(t *testing.T) {
	diff := StringDiff{Previous: "foo"}
	want := "- foo"
	got := diff.String()
	if got != want {
		t.Fatalf("Expected '%s', got '%s'", want, got)
	}
}

func TestStringDiff_Modify(t *testing.T) {
	diff := StringDiff{Previous: "foo", Current: "bar"}
	want := "foo -> bar"
	got := diff.String()
	if got != want {
		t.Fatalf("Expected '%s', got '%s'", want, got)
	}
}

func TestDiffProjects_NoChange(t *testing.T) {
	p1 := gps.NewLockedProject(mkPI("github.com/golang/dep/gps"), gps.NewVersion("v0.10.0"), []string{"gps"})
	p2 := gps.NewLockedProject(mkPI("github.com/golang/dep/gps"), gps.NewVersion("v0.10.0"), []string{"gps"})

	diff := DiffProjects(p1, p2)
	if diff != nil {
		t.Fatal("Expected the diff to be nil")
	}
}

func TestDiffProjects_Modify(t *testing.T) {
	p1 := gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewBranch("master").Pair("abc123"), []string{"baz", "qux"})
	p2 := gps.NewLockedProject(gps.ProjectIdentifier{ProjectRoot: "github.com/foo/bar", Source: "https://github.com/mcfork/gps.git"},
		gps.NewVersion("v1.0.0").Pair("def456"), []string{"baz", "derp"})

	diff := DiffProjects(p1, p2)
	if diff == nil {
		t.Fatal("Expected the diff to be populated")
	}

	wantSource := "+ https://github.com/mcfork/gps.git"
	gotSource := diff.Source.String()
	if gotSource != wantSource {
		t.Fatalf("Expected diff.Source to be '%s', got '%s'", wantSource, diff.Source)
	}

	wantVersion := "+ v1.0.0"
	gotVersion := diff.Version.String()
	if gotVersion != wantVersion {
		t.Fatalf("Expected diff.Version to be '%s', got '%s'", wantVersion, gotVersion)
	}

	wantRevision := "abc123 -> def456"
	gotRevision := diff.Revision.String()
	if gotRevision != wantRevision {
		t.Fatalf("Expected diff.Revision to be '%s', got '%s'", wantRevision, gotRevision)
	}

	wantBranch := "- master"
	gotBranch := diff.Branch.String()
	if gotBranch != wantBranch {
		t.Fatalf("Expected diff.Branch to be '%s', got '%s'", wantBranch, gotBranch)
	}

	fmtPkgs := func(pkgs []StringDiff) string {
		b := bytes.NewBufferString("[")
		for _, pkg := range pkgs {
			b.WriteString(pkg.String())
			b.WriteString(",")
		}
		b.WriteString("]")
		return b.String()
	}

	wantPackages := "[+ derp,- qux,]"
	gotPackages := fmtPkgs(diff.Packages)
	if gotPackages != wantPackages {
		t.Fatalf("Expected diff.Packages to be '%s', got '%s'", wantPackages, gotPackages)
	}
}

func TestDiffProjects_AddPackages(t *testing.T) {
	p1 := gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewBranch("master").Pair("abc123"), []string{"foobar"})
	p2 := gps.NewLockedProject(gps.ProjectIdentifier{ProjectRoot: "github.com/foo/bar", Source: "https://github.com/mcfork/gps.git"},
		gps.NewVersion("v1.0.0").Pair("def456"), []string{"bazqux", "foobar", "zugzug"})

	diff := DiffProjects(p1, p2)
	if diff == nil {
		t.Fatal("Expected the diff to be populated")
	}

	if len(diff.Packages) != 2 {
		t.Fatalf("Expected diff.Packages to have 2 packages, got %d", len(diff.Packages))
	}

	want0 := "+ bazqux"
	got0 := diff.Packages[0].String()
	if got0 != want0 {
		t.Fatalf("Expected diff.Packages[0] to contain %s, got %s", want0, got0)
	}

	want1 := "+ zugzug"
	got1 := diff.Packages[1].String()
	if got1 != want1 {
		t.Fatalf("Expected diff.Packages[1] to contain %s, got %s", want1, got1)
	}
}

func TestDiffProjects_RemovePackages(t *testing.T) {
	p1 := gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewBranch("master").Pair("abc123"), []string{"athing", "foobar"})
	p2 := gps.NewLockedProject(gps.ProjectIdentifier{ProjectRoot: "github.com/foo/bar", Source: "https://github.com/mcfork/gps.git"},
		gps.NewVersion("v1.0.0").Pair("def456"), []string{"bazqux"})

	diff := DiffProjects(p1, p2)
	if diff == nil {
		t.Fatal("Expected the diff to be populated")
	}

	if len(diff.Packages) > 3 {
		t.Fatalf("Expected diff.Packages to have 3 packages, got %d", len(diff.Packages))
	}

	want0 := "- athing"
	got0 := diff.Packages[0].String()
	if got0 != want0 {
		t.Fatalf("Expected diff.Packages[0] to contain %s, got %s", want0, got0)
	}

	// diff.Packages[1] is '+ bazqux'

	want2 := "- foobar"
	got2 := diff.Packages[2].String()
	if got2 != want2 {
		t.Fatalf("Expected diff.Packages[2] to contain %s, got %s", want2, got2)
	}
}

func TestDiffLocks_NoChange(t *testing.T) {
	l1 := gps.SimpleLock{
		gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewVersion("v1.0.0"), nil),
	}
	l2 := gps.SimpleLock{
		gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewVersion("v1.0.0"), nil),
	}

	diff := DiffLocks(l1, l2)
	if diff != nil {
		t.Fatal("Expected the diff to be nil")
	}
}

func TestDiffLocks_AddProjects(t *testing.T) {
	l1 := gps.SimpleLock{
		gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewVersion("v1.0.0"), nil),
	}
	l2 := gps.SimpleLock{
		gps.NewLockedProject(gps.ProjectIdentifier{ProjectRoot: "github.com/baz/qux", Source: "https://github.com/mcfork/bazqux.git"},
			gps.NewVersion("v0.5.0").Pair("def456"), []string{"p1", "p2"}),
		gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewVersion("v1.0.0"), nil),
		gps.NewLockedProject(mkPI("github.com/zug/zug"), gps.NewVersion("v1.0.0"), nil),
	}

	diff := DiffLocks(l1, l2)
	if diff == nil {
		t.Fatal("Expected the diff to be populated")
	}

	if len(diff.Add) != 2 {
		t.Fatalf("Expected diff.Add to have 2 projects, got %d", len(diff.Add))
	}

	want0 := "github.com/baz/qux"
	got0 := string(diff.Add[0].Name)
	if got0 != want0 {
		t.Fatalf("Expected diff.Add[0] to contain %s, got %s", want0, got0)
	}

	want1 := "github.com/zug/zug"
	got1 := string(diff.Add[1].Name)
	if got1 != want1 {
		t.Fatalf("Expected diff.Add[1] to contain %s, got %s", want1, got1)
	}

	add0 := diff.Add[0]
	wantSource := "https://github.com/mcfork/bazqux.git"
	gotSource := add0.Source.String()
	if gotSource != wantSource {
		t.Fatalf("Expected diff.Add[0].Source to be '%s', got '%s'", wantSource, add0.Source)
	}

	wantVersion := "v0.5.0"
	gotVersion := add0.Version.String()
	if gotVersion != wantVersion {
		t.Fatalf("Expected diff.Add[0].Version to be '%s', got '%s'", wantVersion, gotVersion)
	}

	wantRevision := "def456"
	gotRevision := add0.Revision.String()
	if gotRevision != wantRevision {
		t.Fatalf("Expected diff.Add[0].Revision to be '%s', got '%s'", wantRevision, gotRevision)
	}

	wantBranch := ""
	gotBranch := add0.Branch.String()
	if gotBranch != wantBranch {
		t.Fatalf("Expected diff.Add[0].Branch to be '%s', got '%s'", wantBranch, gotBranch)
	}

	fmtPkgs := func(pkgs []StringDiff) string {
		b := bytes.NewBufferString("[")
		for _, pkg := range pkgs {
			b.WriteString(pkg.String())
			b.WriteString(",")
		}
		b.WriteString("]")
		return b.String()
	}

	wantPackages := "[p1,p2,]"
	gotPackages := fmtPkgs(add0.Packages)
	if gotPackages != wantPackages {
		t.Fatalf("Expected diff.Add[0].Packages to be '%s', got '%s'", wantPackages, gotPackages)
	}
}

func TestDiffLocks_RemoveProjects(t *testing.T) {
	l1 := gps.SimpleLock{
		gps.NewLockedProject(gps.ProjectIdentifier{ProjectRoot: "github.com/a/thing", Source: "https://github.com/mcfork/athing.git"},
			gps.NewBranch("master").Pair("def456"), []string{"p1", "p2"}),
		gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewVersion("v1.0.0"), nil),
	}
	l2 := gps.SimpleLock{
		gps.NewLockedProject(mkPI("github.com/baz/qux"), gps.NewVersion("v1.0.0"), nil),
	}

	diff := DiffLocks(l1, l2)
	if diff == nil {
		t.Fatal("Expected the diff to be populated")
	}

	if len(diff.Remove) != 2 {
		t.Fatalf("Expected diff.Remove to have 2 projects, got %d", len(diff.Remove))
	}

	want0 := "github.com/a/thing"
	got0 := string(diff.Remove[0].Name)
	if got0 != want0 {
		t.Fatalf("Expected diff.Remove[0] to contain %s, got %s", want0, got0)
	}

	want1 := "github.com/foo/bar"
	got1 := string(diff.Remove[1].Name)
	if got1 != want1 {
		t.Fatalf("Expected diff.Remove[1] to contain %s, got %s", want1, got1)
	}

	remove0 := diff.Remove[0]
	wantSource := "https://github.com/mcfork/athing.git"
	gotSource := remove0.Source.String()
	if gotSource != wantSource {
		t.Fatalf("Expected diff.Remove[0].Source to be '%s', got '%s'", wantSource, remove0.Source)
	}

	wantVersion := ""
	gotVersion := remove0.Version.String()
	if gotVersion != wantVersion {
		t.Fatalf("Expected diff.Remove[0].Version to be '%s', got '%s'", wantVersion, gotVersion)
	}

	wantRevision := "def456"
	gotRevision := remove0.Revision.String()
	if gotRevision != wantRevision {
		t.Fatalf("Expected diff.Remove[0].Revision to be '%s', got '%s'", wantRevision, gotRevision)
	}

	wantBranch := "master"
	gotBranch := remove0.Branch.String()
	if gotBranch != wantBranch {
		t.Fatalf("Expected diff.Remove[0].Branch to be '%s', got '%s'", wantBranch, gotBranch)
	}

	fmtPkgs := func(pkgs []StringDiff) string {
		b := bytes.NewBufferString("[")
		for _, pkg := range pkgs {
			b.WriteString(pkg.String())
			b.WriteString(",")
		}
		b.WriteString("]")
		return b.String()
	}

	wantPackages := "[p1,p2,]"
	gotPackages := fmtPkgs(remove0.Packages)
	if gotPackages != wantPackages {
		t.Fatalf("Expected diff.Remove[0].Packages to be '%s', got '%s'", wantPackages, gotPackages)
	}
}

func TestDiffLocks_ModifyProjects(t *testing.T) {
	l1 := gps.SimpleLock{
		gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewVersion("v1.0.0"), nil),
		gps.NewLockedProject(mkPI("github.com/foo/bu"), gps.NewVersion("v1.0.0"), nil),
		gps.NewLockedProject(mkPI("github.com/zig/zag"), gps.NewVersion("v1.0.0"), nil),
	}
	l2 := gps.SimpleLock{
		gps.NewLockedProject(mkPI("github.com/baz/qux"), gps.NewVersion("v1.0.0"), nil),
		gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewVersion("v2.0.0"), nil),
		gps.NewLockedProject(mkPI("github.com/zig/zag"), gps.NewVersion("v2.0.0"), nil),
		gps.NewLockedProject(mkPI("github.com/zug/zug"), gps.NewVersion("v1.0.0"), nil),
	}

	diff := DiffLocks(l1, l2)
	if diff == nil {
		t.Fatal("Expected the diff to be populated")
	}

	if len(diff.Modify) != 2 {
		t.Fatalf("Expected diff.Remove to have 2 projects, got %d", len(diff.Remove))
	}

	want0 := "github.com/foo/bar"
	got0 := string(diff.Modify[0].Name)
	if got0 != want0 {
		t.Fatalf("Expected diff.Modify[0] to contain %s, got %s", want0, got0)
	}

	want1 := "github.com/zig/zag"
	got1 := string(diff.Modify[1].Name)
	if got1 != want1 {
		t.Fatalf("Expected diff.Modify[1] to contain %s, got %s", want1, got1)
	}
}

func TestDiffLocks_EmptyInitialLock(t *testing.T) {
	l2 := gps.SimpleLock{
		gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewVersion("v1.0.0"), nil),
	}

	diff := DiffLocks(nil, l2)

	if len(diff.Add) != 1 {
		t.Fatalf("Expected diff.Add to contain 1 project, got %d", len(diff.Add))
	}
}

func TestDiffLocks_EmptyFinalLock(t *testing.T) {
	l1 := gps.SimpleLock{
		gps.NewLockedProject(mkPI("github.com/foo/bar"), gps.NewVersion("v1.0.0"), nil),
	}

	diff := DiffLocks(l1, nil)

	if len(diff.Remove) != 1 {
		t.Fatalf("Expected diff.Remove to contain 1 project, got %d", len(diff.Remove))
	}
}

func TestDiffLocks_EmptyLocks(t *testing.T) {
	diff := DiffLocks(nil, nil)
	if diff != nil {
		t.Fatal("Expected the diff to be empty")
	}
}
