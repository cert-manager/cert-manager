// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/golang/dep/internal/test"
)

// An analyzer that passes nothing back, but doesn't error. This is the naive
// case - no constraints, no lock, and no errors. The SourceManager will
// interpret this as open/Any constraints on everything in the import graph.
type naiveAnalyzer struct{}

func (naiveAnalyzer) DeriveManifestAndLock(string, ProjectRoot) (Manifest, Lock, error) {
	return nil, nil, nil
}

func (a naiveAnalyzer) Info() ProjectAnalyzerInfo {
	return ProjectAnalyzerInfo{
		Name:    "naive-analyzer",
		Version: 1,
	}
}

func mkNaiveSM(t *testing.T) (*SourceMgr, func()) {
	cpath, err := ioutil.TempDir("", "smcache")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %s", err)
	}

	sm, err := NewSourceManager(SourceManagerConfig{
		Cachedir: cpath,
		Logger:   log.New(test.Writer{TB: t}, "", 0),
	})
	if err != nil {
		t.Fatalf("Unexpected error on SourceManager creation: %s", err)
	}

	return sm, func() {
		sm.Release()
		err := os.RemoveAll(cpath)
		if err != nil {
			t.Errorf("removeAll failed: %s", err)
		}
	}
}

func remakeNaiveSM(osm *SourceMgr, t *testing.T) (*SourceMgr, func()) {
	cpath := osm.cachedir
	osm.Release()

	sm, err := NewSourceManager(SourceManagerConfig{
		Cachedir: cpath,
		Logger:   log.New(test.Writer{TB: t}, "", 0),
	})
	if err != nil {
		t.Fatalf("unexpected error on SourceManager recreation: %s", err)
	}

	return sm, func() {
		sm.Release()
		err := os.RemoveAll(cpath)
		if err != nil {
			t.Errorf("removeAll failed: %s", err)
		}
	}
}

func TestSourceManagerInit(t *testing.T) {
	cpath, err := ioutil.TempDir("", "smcache")
	if err != nil {
		t.Errorf("Failed to create temp dir: %s", err)
	}
	cfg := SourceManagerConfig{
		Cachedir: cpath,
		Logger:   log.New(test.Writer{TB: t}, "", 0),
	}

	sm, err := NewSourceManager(cfg)

	if err != nil {
		t.Errorf("Unexpected error on SourceManager creation: %s", err)
	}

	_, err = NewSourceManager(cfg)
	if err == nil {
		t.Errorf("Creating second SourceManager should have failed due to file lock contention")
	} else if te, ok := err.(CouldNotCreateLockError); !ok {
		t.Errorf("Should have gotten CouldNotCreateLockError error type, but got %T", te)
	}

	if _, err = os.Stat(path.Join(cpath, "sm.lock")); err != nil {
		t.Errorf("Global cache lock file not created correctly")
	}

	sm.Release()
	err = os.RemoveAll(cpath)
	if err != nil {
		t.Errorf("removeAll failed: %s", err)
	}

	if _, err = os.Stat(path.Join(cpath, "sm.lock")); !os.IsNotExist(err) {
		t.Fatalf("Global cache lock file not cleared correctly on Release()")
	}

	err = os.MkdirAll(cpath, 0777)
	if err != nil {
		t.Errorf("Failed to re-create temp dir: %s", err)
	}
	defer func() {
		err = os.RemoveAll(cpath)
		if err != nil {
			t.Errorf("removeAll failed: %s", err)
		}
	}()
	// Set another one up at the same spot now, just to be sure
	sm, err = NewSourceManager(cfg)
	if err != nil {
		t.Fatalf("Creating a second SourceManager should have succeeded when the first was released, but failed with err %s", err)
	}

	sm.Release()
}

func TestSourceInit(t *testing.T) {
	// This test is a bit slow, skip it on -short
	if testing.Short() {
		t.Skip("Skipping project manager init test in short mode")
	}

	cpath, err := ioutil.TempDir("", "smcache")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %s", err)
	}

	sm, err := NewSourceManager(SourceManagerConfig{
		Cachedir: cpath,
		Logger:   log.New(test.Writer{TB: t}, "", 0),
	})
	if err != nil {
		t.Fatalf("Unexpected error on SourceManager creation: %s", err)
	}

	defer func() {
		sm.Release()
		err := os.RemoveAll(cpath)
		if err != nil {
			t.Errorf("removeAll failed: %s", err)
		}
	}()

	id := mkPI("github.com/sdboyer/gpkt").normalize()
	pvl, err := sm.ListVersions(id)
	if err != nil {
		t.Errorf("Unexpected error during initial project setup/fetching %s", err)
	}

	if len(pvl) != 7 {
		t.Errorf("Expected seven version results from the test repo, got %v", len(pvl))
	} else {
		expected := []PairedVersion{
			NewVersion("v2.0.0").Pair(Revision("4a54adf81c75375d26d376459c00d5ff9b703e5e")),
			NewVersion("v1.1.0").Pair(Revision("b2cb48dda625f6640b34d9ffb664533359ac8b91")),
			NewVersion("v1.0.0").Pair(Revision("bf85021c0405edbc4f3648b0603818d641674f72")),
			newDefaultBranch("master").Pair(Revision("bf85021c0405edbc4f3648b0603818d641674f72")),
			NewBranch("v1").Pair(Revision("e3777f683305eafca223aefe56b4e8ecf103f467")),
			NewBranch("v1.1").Pair(Revision("f1fbc520489a98306eb28c235204e39fa8a89c84")),
			NewBranch("v3").Pair(Revision("4a54adf81c75375d26d376459c00d5ff9b703e5e")),
		}

		// SourceManager itself doesn't guarantee ordering; sort them here so we
		// can dependably check output
		SortPairedForUpgrade(pvl)

		for k, e := range expected {
			if !pvl[k].Matches(e) {
				t.Errorf("Expected version %s in position %v but got %s", e, k, pvl[k])
			}
		}
	}

	// Two birds, one stone - make sure the internal ProjectManager vlist cache
	// works (or at least doesn't not work) by asking for the versions again,
	// and do it through smcache to ensure its sorting works, as well.
	smc := &bridge{
		sm:     sm,
		vlists: make(map[ProjectIdentifier][]Version),
		s:      &solver{mtr: newMetrics()},
	}

	vl, err := smc.listVersions(id)
	if err != nil {
		t.Errorf("Unexpected error during initial project setup/fetching %s", err)
	}

	if len(vl) != 7 {
		t.Errorf("Expected seven version results from the test repo, got %v", len(vl))
	} else {
		expected := []Version{
			NewVersion("v2.0.0").Pair(Revision("4a54adf81c75375d26d376459c00d5ff9b703e5e")),
			NewVersion("v1.1.0").Pair(Revision("b2cb48dda625f6640b34d9ffb664533359ac8b91")),
			NewVersion("v1.0.0").Pair(Revision("bf85021c0405edbc4f3648b0603818d641674f72")),
			newDefaultBranch("master").Pair(Revision("bf85021c0405edbc4f3648b0603818d641674f72")),
			NewBranch("v1").Pair(Revision("e3777f683305eafca223aefe56b4e8ecf103f467")),
			NewBranch("v1.1").Pair(Revision("f1fbc520489a98306eb28c235204e39fa8a89c84")),
			NewBranch("v3").Pair(Revision("4a54adf81c75375d26d376459c00d5ff9b703e5e")),
		}

		for k, e := range expected {
			if !vl[k].Matches(e) {
				t.Errorf("Expected version %s in position %v but got %s", e, k, vl[k])
			}
		}

		if !vl[3].(versionPair).v.(branchVersion).isDefault {
			t.Error("Expected master branch version to have isDefault flag, but it did not")
		}
		if vl[4].(versionPair).v.(branchVersion).isDefault {
			t.Error("Expected v1 branch version not to have isDefault flag, but it did")
		}
		if vl[5].(versionPair).v.(branchVersion).isDefault {
			t.Error("Expected v1.1 branch version not to have isDefault flag, but it did")
		}
		if vl[6].(versionPair).v.(branchVersion).isDefault {
			t.Error("Expected v3 branch version not to have isDefault flag, but it did")
		}
	}

	present, err := smc.RevisionPresentIn(id, Revision("4a54adf81c75375d26d376459c00d5ff9b703e5e"))
	if err != nil {
		t.Errorf("Should have found revision in source, but got err: %s", err)
	} else if !present {
		t.Errorf("Should have found revision in source, but did not")
	}

	// SyncSourceFor will ensure we have everything
	err = smc.SyncSourceFor(id)
	if err != nil {
		t.Errorf("SyncSourceFor failed with unexpected error: %s", err)
	}

	// Ensure that the appropriate cache dirs and files exist
	_, err = os.Stat(filepath.Join(cpath, "sources", "https---github.com-sdboyer-gpkt", ".git"))
	if err != nil {
		t.Error("Cache repo does not exist in expected location")
	}

	os.Stat(filepath.Join(cpath, "metadata", "github.com", "sdboyer", "gpkt", "cache.json"))

	// Ensure source existence values are what we expect
	var exists bool
	exists, err = sm.SourceExists(id)
	if err != nil {
		t.Errorf("Error on checking SourceExists: %s", err)
	}
	if !exists {
		t.Error("Source should exist after non-erroring call to ListVersions")
	}
}

func TestDefaultBranchAssignment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping default branch assignment test in short mode")
	}

	sm, clean := mkNaiveSM(t)
	defer clean()

	id := mkPI("github.com/sdboyer/test-multibranch")
	v, err := sm.ListVersions(id)
	if err != nil {
		t.Errorf("Unexpected error during initial project setup/fetching %s", err)
	}

	if len(v) != 3 {
		t.Errorf("Expected three version results from the test repo, got %v", len(v))
	} else {
		brev := Revision("fda020843ac81352004b9dca3fcccdd517600149")
		mrev := Revision("9f9c3a591773d9b28128309ac7a9a72abcab267d")
		expected := []PairedVersion{
			NewBranch("branchone").Pair(brev),
			NewBranch("otherbranch").Pair(brev),
			NewBranch("master").Pair(mrev),
		}

		SortPairedForUpgrade(v)

		for k, e := range expected {
			if !v[k].Matches(e) {
				t.Errorf("Expected version %s in position %v but got %s", e, k, v[k])
			}
		}

		if !v[0].(versionPair).v.(branchVersion).isDefault {
			t.Error("Expected branchone branch version to have isDefault flag, but it did not")
		}
		if !v[0].(versionPair).v.(branchVersion).isDefault {
			t.Error("Expected otherbranch branch version to have isDefault flag, but it did not")
		}
		if v[2].(versionPair).v.(branchVersion).isDefault {
			t.Error("Expected master branch version not to have isDefault flag, but it did")
		}
	}
}

func TestMgrMethodsFailWithBadPath(t *testing.T) {
	// a symbol will always bork it up
	bad := mkPI("foo/##&^").normalize()
	sm, clean := mkNaiveSM(t)
	defer clean()

	var err error
	if _, err = sm.SourceExists(bad); err == nil {
		t.Error("SourceExists() did not error on bad input")
	}
	if err = sm.SyncSourceFor(bad); err == nil {
		t.Error("SyncSourceFor() did not error on bad input")
	}
	if _, err = sm.ListVersions(bad); err == nil {
		t.Error("ListVersions() did not error on bad input")
	}
	if _, err = sm.RevisionPresentIn(bad, Revision("")); err == nil {
		t.Error("RevisionPresentIn() did not error on bad input")
	}
	if _, err = sm.ListPackages(bad, nil); err == nil {
		t.Error("ListPackages() did not error on bad input")
	}
	if _, _, err = sm.GetManifestAndLock(bad, nil, naiveAnalyzer{}); err == nil {
		t.Error("GetManifestAndLock() did not error on bad input")
	}
	if err = sm.ExportProject(context.Background(), bad, nil, ""); err == nil {
		t.Error("ExportProject() did not error on bad input")
	}
}

type sourceCreationTestFixture struct {
	roots               []ProjectIdentifier
	namecount, srccount int
}

func (f sourceCreationTestFixture) run(t *testing.T) {
	t.Parallel()
	sm, clean := mkNaiveSM(t)
	defer clean()

	for _, pi := range f.roots {
		_, err := sm.SourceExists(pi)
		if err != nil {
			t.Fatal(err)
		}
	}

	if len(sm.srcCoord.nameToURL) != f.namecount {
		t.Errorf("want %v names in the name->url map, but got %v. contents: \n%v", f.namecount, len(sm.srcCoord.nameToURL), sm.srcCoord.nameToURL)
	}

	if len(sm.srcCoord.srcs) != f.srccount {
		t.Errorf("want %v gateways in the sources map, but got %v", f.srccount, len(sm.srcCoord.srcs))
	}

	if t.Failed() {
		var keys []string
		for k := range sm.srcCoord.nameToURL {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var buf bytes.Buffer
		w := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
		fmt.Fprint(w, "NAME\tMAPPED URL\n")
		for _, r := range keys {
			fmt.Fprintf(w, "%s\t%s\n", r, sm.srcCoord.nameToURL[r])
		}
		w.Flush()
		t.Log("\n", buf.String())

		t.Log("SRC KEYS")
		for k := range sm.srcCoord.srcs {
			t.Log(k)
		}
	}
}

// This test is primarily about making sure that the logic around folding
// together different ways of referencing the same underlying resource - whether
// that be intentionally folding them, or intentionally keeping them separate -
// work as intended.
func TestSourceCreationCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	fixtures := map[string]sourceCreationTestFixture{
		"gopkgin uniqueness": {
			roots: []ProjectIdentifier{
				mkPI("gopkg.in/sdboyer/gpkt.v1"),
				mkPI("gopkg.in/sdboyer/gpkt.v2"),
				mkPI("gopkg.in/sdboyer/gpkt.v3"),
			},
			namecount: 6,
			srccount:  3,
		},
		"gopkgin separation from github": {
			roots: []ProjectIdentifier{
				mkPI("gopkg.in/sdboyer/gpkt.v1"),
				mkPI("github.com/sdboyer/gpkt"),
				mkPI("http://github.com/sdboyer/gpkt"),
				mkPI("https://github.com/sdboyer/gpkt"),
			},
			namecount: 5,
			srccount:  3,
		},
		"case variance across path and URL-based access": {
			roots: []ProjectIdentifier{
				{ProjectRoot: ProjectRoot("github.com/sdboyer/gpkt"), Source: "https://github.com/Sdboyer/gpkt"},
				{ProjectRoot: ProjectRoot("github.com/sdboyer/gpkt"), Source: "https://github.com/SdbOyer/gpkt"},
				mkPI("github.com/sdboyer/gpkt"),
				{ProjectRoot: ProjectRoot("github.com/sdboyer/gpkt"), Source: "https://github.com/sdboyeR/gpkt"},
				mkPI("github.com/sdboyeR/gpkt"),
			},
			namecount: 6,
			srccount:  1,
		},
	}

	for name, fix := range fixtures {
		t.Run(name, fix.run)
	}
}

func TestGetSources(t *testing.T) {
	// This test is a tad slow, skip it on -short
	if testing.Short() {
		t.Skip("Skipping source setup test in short mode")
	}
	requiresBins(t, "git", "hg", "bzr")

	sm, clean := mkNaiveSM(t)

	pil := []ProjectIdentifier{
		mkPI("github.com/Masterminds/VCSTestRepo").normalize(),
		mkPI("bitbucket.org/mattfarina/testhgrepo").normalize(),
		mkPI("launchpad.net/govcstestbzrrepo").normalize(),
	}

	ctx := context.Background()
	// protects against premature release of sm
	t.Run("inner", func(t *testing.T) {
		for _, pi := range pil {
			lpi := pi
			t.Run(lpi.normalizedSource(), func(t *testing.T) {
				t.Parallel()

				srcg, err := sm.srcCoord.getSourceGatewayFor(ctx, lpi)
				if err != nil {
					t.Errorf("unexpected error setting up source: %s", err)
					return
				}

				// Re-get the same, make sure they are the same
				srcg2, err := sm.srcCoord.getSourceGatewayFor(ctx, lpi)
				if err != nil {
					t.Errorf("unexpected error re-getting source: %s", err)
				} else if srcg != srcg2 {
					t.Error("first and second sources are not eq")
				}

				// All of them _should_ select https, so this should work
				lpi.Source = "https://" + lpi.Source
				srcg3, err := sm.srcCoord.getSourceGatewayFor(ctx, lpi)
				if err != nil {
					t.Errorf("unexpected error getting explicit https source: %s", err)
				} else if srcg != srcg3 {
					t.Error("explicit https source should reuse autodetected https source")
				}

				// Now put in http, and they should differ
				lpi.Source = "http://" + string(lpi.ProjectRoot)
				srcg4, err := sm.srcCoord.getSourceGatewayFor(ctx, lpi)
				if err != nil {
					t.Errorf("unexpected error getting explicit http source: %s", err)
				} else if srcg == srcg4 {
					t.Error("explicit http source should create a new src")
				}
			})
		}
	})

	// nine entries (of which three are dupes): for each vcs, raw import path,
	// the https url, and the http url. also three more from case folding of
	// github.com/Masterminds/VCSTestRepo -> github.com/masterminds/vcstestrepo
	if len(sm.srcCoord.nameToURL) != 12 {
		t.Errorf("Should have twelve discrete entries in the nameToURL map, got %v", len(sm.srcCoord.nameToURL))
	}
	clean()
}

func TestFSCaseSensitivityConvergesSources(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	f := func(name string, pi1, pi2 ProjectIdentifier) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sm, clean := mkNaiveSM(t)
			defer clean()

			sm.SyncSourceFor(pi1)
			sg1, err := sm.srcCoord.getSourceGatewayFor(context.Background(), pi1)
			if err != nil {
				t.Fatal(err)
			}

			sm.SyncSourceFor(pi2)
			sg2, err := sm.srcCoord.getSourceGatewayFor(context.Background(), pi2)
			if err != nil {
				t.Fatal(err)
			}

			path1 := sg1.src.(*gitSource).repo.LocalPath()
			stat1, err := os.Stat(path1)
			if err != nil {
				t.Fatal("path1:", path1, err)
			}
			path2 := sg2.src.(*gitSource).repo.LocalPath()
			stat2, err := os.Stat(path2)
			if err != nil {
				t.Fatal("path2:", path2, err)
			}

			same, count := os.SameFile(stat1, stat2), len(sm.srcCoord.srcs)
			if same && count != 1 {
				t.Log("are same, count", count)
				t.Fatal("on case-insensitive filesystem, case-varying sources should have been folded together but were not")
			}
			if !same && count != 2 {
				t.Log("not same, count", count)
				t.Fatal("on case-sensitive filesystem, case-varying sources should not have been folded together, but were")
			}
		})
	}

	folded := mkPI("github.com/sdboyer/deptest").normalize()
	casevar1 := mkPI("github.com/Sdboyer/deptest").normalize()
	casevar2 := mkPI("github.com/SdboyeR/deptest").normalize()
	f("folded first", folded, casevar1)
	f("folded second", casevar1, folded)
	f("both unfolded", casevar1, casevar2)
}

// Regression test for #32
func TestGetInfoListVersionsOrdering(t *testing.T) {
	// This test is quite slow, skip it on -short
	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	sm, clean := mkNaiveSM(t)
	defer clean()

	// setup done, now do the test

	id := mkPI("github.com/sdboyer/gpkt").normalize()

	_, _, err := sm.GetManifestAndLock(id, NewVersion("v1.0.0"), naiveAnalyzer{})
	if err != nil {
		t.Errorf("Unexpected error from GetInfoAt %s", err)
	}

	v, err := sm.ListVersions(id)
	if err != nil {
		t.Errorf("Unexpected error from ListVersions %s", err)
	}

	if len(v) != 7 {
		t.Errorf("Expected seven results from ListVersions, got %v", len(v))
	}
}

func TestDeduceProjectRoot(t *testing.T) {
	sm, clean := mkNaiveSM(t)
	defer clean()

	in := "github.com/sdboyer/gps"
	pr, err := sm.DeduceProjectRoot(in)
	if err != nil {
		t.Errorf("Problem while detecting root of %q %s", in, err)
	}
	if string(pr) != in {
		t.Errorf("Wrong project root was deduced;\n\t(GOT) %s\n\t(WNT) %s", pr, in)
	}
	if sm.deduceCoord.rootxt.Len() != 1 {
		t.Errorf("Root path trie should have one element after one deduction, has %v", sm.deduceCoord.rootxt.Len())
	}

	pr, err = sm.DeduceProjectRoot(in)
	if err != nil {
		t.Errorf("Problem while detecting root of %q %s", in, err)
	} else if string(pr) != in {
		t.Errorf("Wrong project root was deduced;\n\t(GOT) %s\n\t(WNT) %s", pr, in)
	}
	if sm.deduceCoord.rootxt.Len() != 1 {
		t.Errorf("Root path trie should still have one element after performing the same deduction twice; has %v", sm.deduceCoord.rootxt.Len())
	}

	// Now do a subpath
	sub := path.Join(in, "foo")
	pr, err = sm.DeduceProjectRoot(sub)
	if err != nil {
		t.Errorf("Problem while detecting root of %q %s", sub, err)
	} else if string(pr) != in {
		t.Errorf("Wrong project root was deduced;\n\t(GOT) %s\n\t(WNT) %s", pr, in)
	}
	if sm.deduceCoord.rootxt.Len() != 1 {
		t.Errorf("Root path trie should still have one element, as still only one unique root has gone in; has %v", sm.deduceCoord.rootxt.Len())
	}

	// Now do a fully different root, but still on github
	in2 := "github.com/bagel/lox"
	sub2 := path.Join(in2, "cheese")
	pr, err = sm.DeduceProjectRoot(sub2)
	if err != nil {
		t.Errorf("Problem while detecting root of %q %s", sub2, err)
	} else if string(pr) != in2 {
		t.Errorf("Wrong project root was deduced;\n\t(GOT) %s\n\t(WNT) %s", pr, in)
	}
	if sm.deduceCoord.rootxt.Len() != 2 {
		t.Errorf("Root path trie should have two elements, one for each unique root; has %v", sm.deduceCoord.rootxt.Len())
	}

	// Ensure that our prefixes are bounded by path separators
	in4 := "github.com/bagel/loxx"
	pr, err = sm.DeduceProjectRoot(in4)
	if err != nil {
		t.Errorf("Problem while detecting root of %q %s", in4, err)
	} else if string(pr) != in4 {
		t.Errorf("Wrong project root was deduced;\n\t(GOT) %s\n\t(WNT) %s", pr, in)
	}
	if sm.deduceCoord.rootxt.Len() != 3 {
		t.Errorf("Root path trie should have three elements, one for each unique root; has %v", sm.deduceCoord.rootxt.Len())
	}

	// Ensure that vcs extension-based matching comes through
	in5 := "ffffrrrraaaaaapppppdoesnotresolve.com/baz.git"
	pr, err = sm.DeduceProjectRoot(in5)
	if err != nil {
		t.Errorf("Problem while detecting root of %q %s", in5, err)
	} else if string(pr) != in5 {
		t.Errorf("Wrong project root was deduced;\n\t(GOT) %s\n\t(WNT) %s", pr, in)
	}
	if sm.deduceCoord.rootxt.Len() != 4 {
		t.Errorf("Root path trie should have four elements, one for each unique root; has %v", sm.deduceCoord.rootxt.Len())
	}
}

func TestMultiFetchThreadsafe(t *testing.T) {
	// This test is quite slow, skip it on -short
	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	projects := []ProjectIdentifier{
		mkPI("github.com/sdboyer/gps"),
		mkPI("github.com/sdboyer/gpkt"),
		{
			ProjectRoot: ProjectRoot("github.com/sdboyer/gpkt"),
			Source:      "https://github.com/sdboyer/gpkt",
		},
		mkPI("github.com/sdboyer/gogl"),
		mkPI("github.com/sdboyer/gliph"),
		mkPI("github.com/sdboyer/frozone"),
		mkPI("gopkg.in/sdboyer/gpkt.v1"),
		mkPI("gopkg.in/sdboyer/gpkt.v2"),
		mkPI("github.com/Masterminds/VCSTestRepo"),
		mkPI("github.com/go-yaml/yaml"),
		mkPI("github.com/sirupsen/logrus"),
		mkPI("github.com/Masterminds/semver"),
		mkPI("github.com/Masterminds/vcs"),
		//mkPI("bitbucket.org/sdboyer/withbm"),
		//mkPI("bitbucket.org/sdboyer/nobm"),
	}

	do := func(name string, sm SourceManager) {
		t.Run(name, func(t *testing.T) {
			// This gives us ten calls per op, per project, which should be(?)
			// decently likely to reveal underlying concurrency problems
			ops := 4
			cnum := len(projects) * ops * 10

			for i := 0; i < cnum; i++ {
				// Trigger all four ops on each project, then move on to the next
				// project.
				id, op := projects[(i/ops)%len(projects)], i%ops
				// The count of times this op has been been invoked on this project
				// (after the upcoming invocation)
				opcount := i/(ops*len(projects)) + 1

				switch op {
				case 0:
					t.Run(fmt.Sprintf("deduce:%v:%s", opcount, id), func(t *testing.T) {
						t.Parallel()
						if _, err := sm.DeduceProjectRoot(string(id.ProjectRoot)); err != nil {
							t.Error(err)
						}
					})
				case 1:
					t.Run(fmt.Sprintf("sync:%v:%s", opcount, id), func(t *testing.T) {
						t.Parallel()
						err := sm.SyncSourceFor(id)
						if err != nil {
							t.Error(err)
						}
					})
				case 2:
					t.Run(fmt.Sprintf("listVersions:%v:%s", opcount, id), func(t *testing.T) {
						t.Parallel()
						vl, err := sm.ListVersions(id)
						if err != nil {
							t.Fatal(err)
						}
						if len(vl) == 0 {
							t.Error("no versions returned")
						}
					})
				case 3:
					t.Run(fmt.Sprintf("exists:%v:%s", opcount, id), func(t *testing.T) {
						t.Parallel()
						y, err := sm.SourceExists(id)
						if err != nil {
							t.Fatal(err)
						}
						if !y {
							t.Error("said source does not exist")
						}
					})
				default:
					panic(fmt.Sprintf("wtf, %s %v", id, op))
				}
			}
		})
	}

	sm, _ := mkNaiveSM(t)
	do("first", sm)

	// Run the thing twice with a remade sm so that we cover both the cases of
	// pre-existing and new clones.
	//
	// This triggers a release of the first sm, which is much of what we're
	// testing here - that the release is complete and clean, and can be
	// immediately followed by a new sm coming in.
	sm2, clean := remakeNaiveSM(sm, t)
	do("second", sm2)
	clean()
}

// Ensure that we don't see concurrent map writes when calling ListVersions.
// Regression test for https://github.com/sdboyer/gps/issues/156.
//
// Ideally this would be caught by TestMultiFetchThreadsafe, but perhaps the
// high degree of parallelism pretty much eliminates that as a realistic
// possibility?
func TestListVersionsRacey(t *testing.T) {
	// This test is quite slow, skip it on -short
	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	sm, clean := mkNaiveSM(t)
	defer clean()

	wg := &sync.WaitGroup{}
	id := mkPI("github.com/sdboyer/gps")
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			_, err := sm.ListVersions(id)
			if err != nil {
				t.Errorf("listing versions failed with err %s", err.Error())
			}
			wg.Done()
		}()
	}

	wg.Wait()
}

func TestErrAfterRelease(t *testing.T) {
	sm, clean := mkNaiveSM(t)
	clean()
	id := ProjectIdentifier{}

	_, err := sm.SourceExists(id)
	if err == nil {
		t.Errorf("SourceExists did not error after calling Release()")
	} else if err != ErrSourceManagerIsReleased {
		t.Errorf("SourceExists errored after Release(), but with unexpected error: %T %s", err, err.Error())
	}

	err = sm.SyncSourceFor(id)
	if err == nil {
		t.Errorf("SyncSourceFor did not error after calling Release()")
	} else if err != ErrSourceManagerIsReleased {
		t.Errorf("SyncSourceFor errored after Release(), but with unexpected error: %T %s", err, err.Error())
	}

	_, err = sm.ListVersions(id)
	if err == nil {
		t.Errorf("ListVersions did not error after calling Release()")
	} else if err != ErrSourceManagerIsReleased {
		t.Errorf("ListVersions errored after Release(), but with unexpected error: %T %s", err, err.Error())
	}

	_, err = sm.RevisionPresentIn(id, "")
	if err == nil {
		t.Errorf("RevisionPresentIn did not error after calling Release()")
	} else if err != ErrSourceManagerIsReleased {
		t.Errorf("RevisionPresentIn errored after Release(), but with unexpected error: %T %s", err, err.Error())
	}

	_, err = sm.ListPackages(id, nil)
	if err == nil {
		t.Errorf("ListPackages did not error after calling Release()")
	} else if err != ErrSourceManagerIsReleased {
		t.Errorf("ListPackages errored after Release(), but with unexpected error: %T %s", err, err.Error())
	}

	_, _, err = sm.GetManifestAndLock(id, nil, naiveAnalyzer{})
	if err == nil {
		t.Errorf("GetManifestAndLock did not error after calling Release()")
	} else if err != ErrSourceManagerIsReleased {
		t.Errorf("GetManifestAndLock errored after Release(), but with unexpected error: %T %s", err, err.Error())
	}

	err = sm.ExportProject(context.Background(), id, nil, "")
	if err == nil {
		t.Errorf("ExportProject did not error after calling Release()")
	} else if err != ErrSourceManagerIsReleased {
		t.Errorf("ExportProject errored after Release(), but with unexpected error: %T %s", err, err.Error())
	}

	_, err = sm.DeduceProjectRoot("")
	if err == nil {
		t.Errorf("DeduceProjectRoot did not error after calling Release()")
	} else if err != ErrSourceManagerIsReleased {
		t.Errorf("DeduceProjectRoot errored after Release(), but with unexpected error: %T %s", err, err.Error())
	}
}

func TestSignalHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	sm, clean := mkNaiveSM(t)

	sigch := make(chan os.Signal)
	sm.HandleSignals(sigch)

	sigch <- os.Interrupt
	<-time.After(10 * time.Millisecond)

	if atomic.LoadInt32(&sm.releasing) != 1 {
		t.Error("Releasing flag did not get set")
	}

	clean()

	// Test again, this time with a running call
	sm, clean = mkNaiveSM(t)
	sm.HandleSignals(sigch)

	errchan := make(chan error)
	go func() {
		_, callerr := sm.DeduceProjectRoot("k8s.io/kubernetes")
		errchan <- callerr
	}()
	go func() { sigch <- os.Interrupt }()
	runtime.Gosched()

	callerr := <-errchan
	if callerr == nil {
		t.Error("network call could not have completed before cancellation, should have gotten an error")
	}
	if atomic.LoadInt32(&sm.releasing) != 1 {
		t.Error("Releasing flag did not get set")
	}
	clean()

	sm, clean = mkNaiveSM(t)
	// Ensure that handling also works after stopping and restarting itself,
	// and that Release happens only once.
	sm.UseDefaultSignalHandling()
	sm.StopSignalHandling()
	sm.HandleSignals(sigch)

	go func() {
		_, callerr := sm.DeduceProjectRoot("k8s.io/kubernetes")
		errchan <- callerr
	}()
	go func() {
		sigch <- os.Interrupt
		sm.Release()
	}()
	runtime.Gosched()

	after := time.After(2 * time.Second)
	select {
	case <-sm.qch:
	case <-after:
		t.Error("did not shut down in reasonable time")
	}

	clean()
}

func TestUnreachableSource(t *testing.T) {
	// If a git remote is unreachable (maybe the server is only accessible behind a VPN, or
	// something), we should return a clear error, not a panic.
	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	sm, clean := mkNaiveSM(t)
	defer clean()

	id := mkPI("github.com/golang/notexist").normalize()
	err := sm.SyncSourceFor(id)
	if err == nil {
		t.Error("expected err when listing versions of a bogus source, but got nil")
	}
}

func TestSupervisor(t *testing.T) {
	bgc := context.Background()
	ctx, cancelFunc := context.WithCancel(bgc)
	superv := newSupervisor(ctx)

	ci := callInfo{
		name: "foo",
		typ:  0,
	}

	_, err := superv.start(ci)
	if err != nil {
		t.Fatal("unexpected err on setUpCall:", err)
	}

	tc, exists := superv.running[ci]
	if !exists {
		t.Fatal("running call not recorded in map")
	}

	if tc.count != 1 {
		t.Fatalf("wrong count of running ci: wanted 1 got %v", tc.count)
	}

	// run another, but via do
	block, wait := make(chan struct{}), make(chan struct{})
	errchan := make(chan error)
	go func() {
		wait <- struct{}{}
		err := superv.do(bgc, "foo", 0, func(ctx context.Context) error {
			<-block
			return nil
		})
		errchan <- err
		//if err != nil {
		//	t.Fatal("unexpected err on do() completion:", err)
		//}
		close(wait)
	}()
	<-wait

	superv.mu.Lock()
	tc, exists = superv.running[ci]
	if !exists {
		t.Fatal("running call not recorded in map")
	}

	// TODO (kris-nova) We need to disable this bypass here, and in the .travis.yml
	// as soon as dep#501 is fixed
	bypass := os.Getenv("DEPTESTBYPASS501")
	if bypass != "" {
		t.Log("bypassing tc.count check for running ci")
	} else if tc.count != 2 {
		t.Fatalf("wrong count of running ci: wanted 2 got %v", tc.count)
	}
	superv.mu.Unlock()

	close(block)

	possibleConcurrentError := <-errchan
	if possibleConcurrentError != nil {
		t.Fatal("unexpected err on do() completion:", err)
	}

	<-wait
	superv.mu.Lock()
	if len(superv.ran) != 0 {
		t.Fatal("should not record metrics until last one drops")
	}

	tc, exists = superv.running[ci]
	if !exists {
		t.Fatal("running call not recorded in map")
	}

	if tc.count != 1 {
		t.Fatalf("wrong count of running ci: wanted 1 got %v", tc.count)
	}
	superv.mu.Unlock()

	superv.done(ci)
	superv.mu.Lock()
	ran, exists := superv.ran[0]
	if !exists {
		t.Fatal("should have metrics after closing last of a ci, but did not")
	}

	if ran.count != 1 {
		t.Fatalf("wrong count of serial runs of a call: wanted 1 got %v", ran.count)
	}
	superv.mu.Unlock()

	cancelFunc()
	_, err = superv.start(ci)
	if err == nil {
		t.Fatal("should have errored on cm.run() after canceling cm's input context")
	}

	superv.do(bgc, "foo", 0, func(ctx context.Context) error {
		t.Fatal("calls should not be initiated by do() after main context is cancelled")
		return nil
	})
}
