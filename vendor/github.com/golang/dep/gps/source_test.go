// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/dep/gps/pkgtree"
	"github.com/golang/dep/internal/test"
)

// Executed in parallel by TestSlowVcs
func testSourceGateway(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping gateway testing in short mode")
	}
	requiresBins(t, "git")

	cachedir, err := ioutil.TempDir("", "smcache")
	if err != nil {
		t.Fatalf("failed to create temp dir: %s", err)
	}
	bgc := context.Background()
	ctx, cancelFunc := context.WithCancel(bgc)
	defer func() {
		os.RemoveAll(cachedir)
		cancelFunc()
	}()
	os.Mkdir(filepath.Join(cachedir, "sources"), 0777)

	do := func(wantstate sourceState) func(t *testing.T) {
		return func(t *testing.T) {
			superv := newSupervisor(ctx)
			deducer := newDeductionCoordinator(superv)
			logger := log.New(test.Writer{TB: t}, "", 0)
			sc := newSourceCoordinator(superv, deducer, cachedir, nil, logger)
			defer sc.close()

			id := mkPI("github.com/sdboyer/deptest")
			sg, err := sc.getSourceGatewayFor(ctx, id)
			if err != nil {
				t.Fatal(err)
			}

			if sg.srcState != wantstate {
				t.Fatalf("expected state to be %q, got %q", wantstate, sg.srcState)
			}

			if err := sg.existsUpstream(ctx); err != nil {
				t.Fatalf("failed to verify upstream source: %s", err)
			}

			wantstate |= sourceExistsUpstream
			if sg.src.existsCallsListVersions() {
				wantstate |= sourceHasLatestVersionList
			}
			if sg.srcState != wantstate {
				t.Fatalf("expected state to be %q, got %q", wantstate, sg.srcState)
			}

			if err := sg.syncLocal(ctx); err != nil {
				t.Fatalf("error on cloning git repo: %s", err)
			}

			wantstate |= sourceExistsLocally | sourceHasLatestLocally
			if sg.srcState != wantstate {
				t.Fatalf("expected state to be %q, got %q", wantstate, sg.srcState)
			}

			if _, ok := sg.src.(*gitSource); !ok {
				t.Fatalf("Expected a gitSource, got a %T", sg.src)
			}

			vlist, err := sg.listVersions(ctx)
			if err != nil {
				t.Fatalf("Unexpected error getting version pairs from git repo: %s", err)
			}

			wantstate |= sourceHasLatestVersionList
			if sg.srcState != wantstate {
				t.Fatalf("expected state to be %q, got %q", wantstate, sg.srcState)
			}

			if len(vlist) != 4 {
				t.Fatalf("git test repo should've produced four versions, got %v: vlist was %s", len(vlist), vlist)
			} else {
				SortPairedForUpgrade(vlist)
				evl := []PairedVersion{
					NewVersion("v1.0.0").Pair(Revision("ff2948a2ac8f538c4ecd55962e919d1e13e74baf")),
					NewVersion("v0.8.1").Pair(Revision("3f4c3bea144e112a69bbe5d8d01c1b09a544253f")),
					NewVersion("v0.8.0").Pair(Revision("ff2948a2ac8f538c4ecd55962e919d1e13e74baf")),
					newDefaultBranch("master").Pair(Revision("3f4c3bea144e112a69bbe5d8d01c1b09a544253f")),
				}
				if len(evl) != len(vlist) {
					t.Errorf("expected %d versions but got %d", len(evl), len(vlist))
				} else {
					for i := range evl {
						if !evl[i].identical(vlist[i]) {
							t.Errorf("index %d: expected version identical to %#v but got %#v", i, evl[i], vlist[i])
						}
					}
				}
			}

			rev := Revision("c575196502940c07bf89fd6d95e83b999162e051")
			// check that an expected rev is not in cache
			_, has := sg.cache.getVersionsFor(rev)
			if has {
				t.Fatal("shouldn't have bare revs in cache without specifically requesting them")
			}

			is, err := sg.revisionPresentIn(ctx, rev)
			if err != nil {
				t.Fatalf("unexpected error while checking revision presence: %s", err)
			} else if !is {
				t.Fatalf("revision that should exist was not present")
			}

			// check that an expected rev is not in cache
			_, has = sg.cache.getVersionsFor(rev)
			if !has {
				t.Fatal("bare rev should be in cache after specific request for it")
			}

			// Ensure that a bad rev doesn't work on any method that takes
			// versions
			badver := NewVersion("notexist")
			wanterr := fmt.Errorf("version %q does not exist in source", badver)

			_, _, err = sg.getManifestAndLock(ctx, ProjectRoot("github.com/sdboyer/deptest"), badver, naiveAnalyzer{})
			if err == nil {
				t.Fatal("wanted err on nonexistent version")
			} else if err.Error() != wanterr.Error() {
				t.Fatalf("wanted nonexistent err when passing bad version, got: %s", err)
			}

			_, err = sg.listPackages(ctx, ProjectRoot("github.com/sdboyer/deptest"), badver)
			if err == nil {
				t.Fatal("wanted err on nonexistent version")
			} else if err.Error() != wanterr.Error() {
				t.Fatalf("wanted nonexistent err when passing bad version, got: %s", err)
			}

			err = sg.exportVersionTo(ctx, badver, cachedir)
			if err == nil {
				t.Fatal("wanted err on nonexistent version")
			} else if err.Error() != wanterr.Error() {
				t.Fatalf("wanted nonexistent err when passing bad version, got: %s", err)
			}

			wantptree := pkgtree.PackageTree{
				ImportRoot: "github.com/sdboyer/deptest",
				Packages: map[string]pkgtree.PackageOrErr{
					"github.com/sdboyer/deptest": {
						P: pkgtree.Package{
							ImportPath: "github.com/sdboyer/deptest",
							Name:       "deptest",
							Imports:    []string{},
						},
					},
				},
			}

			ptree, err := sg.listPackages(ctx, ProjectRoot("github.com/sdboyer/deptest"), Revision("ff2948a2ac8f538c4ecd55962e919d1e13e74baf"))
			if err != nil {
				t.Fatalf("unexpected err when getting package tree with known rev: %s", err)
			}
			comparePackageTree(t, wantptree, ptree)

			ptree, err = sg.listPackages(ctx, ProjectRoot("github.com/sdboyer/deptest"), NewVersion("v1.0.0"))
			if err != nil {
				t.Fatalf("unexpected err when getting package tree with unpaired good version: %s", err)
			}
			comparePackageTree(t, wantptree, ptree)
		}
	}

	// Run test twice so that we cover both the existing and non-existing case.
	t.Run("empty", do(sourceExistsUpstream|sourceHasLatestVersionList))
	t.Run("exists", do(sourceExistsLocally))
}
