// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"context"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/golang/dep/internal/test"
)

// Parent test that executes all the slow vcs interaction tests in parallel.
func TestSlowVcs(t *testing.T) {
	t.Run("write-deptree", testWriteDepTree)
	t.Run("source-gateway", testSourceGateway)
	t.Run("bzr-repo", testBzrRepo)
	t.Run("bzr-source", testBzrSourceInteractions)
	t.Run("svn-repo", testSvnRepo)
	// TODO(sdboyer) svn-source
	t.Run("hg-repo", testHgRepo)
	t.Run("hg-source", testHgSourceInteractions)
	t.Run("git-repo", testGitRepo)
	t.Run("git-source", testGitSourceInteractions)
	t.Run("gopkgin-source", testGopkginSourceInteractions)
}

func testGitSourceInteractions(t *testing.T) {
	t.Parallel()

	// This test is slowish, skip it on -short
	if testing.Short() {
		t.Skip("Skipping git source version fetching test in short mode")
	}
	requiresBins(t, "git")

	cpath, err := ioutil.TempDir("", "smcache")
	if err != nil {
		t.Errorf("Failed to create temp dir: %s", err)
	}
	defer func() {
		if err := os.RemoveAll(cpath); err != nil {
			t.Errorf("removeAll failed: %s", err)
		}
	}()
	os.Mkdir(filepath.Join(cpath, "sources"), 0777)

	n := "github.com/sdboyer/gpkt"
	un := "https://" + n
	u, err := url.Parse(un)
	if err != nil {
		t.Fatalf("Error parsing URL %s: %s", un, err)
	}
	mb := maybeGitSource{
		url: u,
	}

	ctx := context.Background()
	isrc, err := mb.try(ctx, cpath)
	if err != nil {
		t.Fatalf("Unexpected error while setting up gitSource for test repo: %s", err)
	}

	err = isrc.initLocal(ctx)
	if err != nil {
		t.Fatalf("Error on cloning git repo: %s", err)
	}

	src, ok := isrc.(*gitSource)
	if !ok {
		t.Fatalf("Expected a gitSource, got a %T", isrc)
	}

	if un != src.upstreamURL() {
		t.Errorf("Expected %s as source URL, got %s", un, src.upstreamURL())
	}

	pvlist, err := src.listVersions(ctx)
	if err != nil {
		t.Fatalf("Unexpected error getting version pairs from git repo: %s", err)
	}

	vlist := hidePair(pvlist)
	// check that an expected rev is present
	is, err := src.revisionPresentIn(Revision("4a54adf81c75375d26d376459c00d5ff9b703e5e"))
	if err != nil {
		t.Errorf("Unexpected error while checking revision presence: %s", err)
	} else if !is {
		t.Errorf("Revision that should exist was not present")
	}

	if len(vlist) != 7 {
		t.Errorf("git test repo should've produced seven versions, got %v: vlist was %s", len(vlist), vlist)
	} else {
		SortForUpgrade(vlist)
		evl := []Version{
			NewVersion("v2.0.0").Pair(Revision("4a54adf81c75375d26d376459c00d5ff9b703e5e")),
			NewVersion("v1.1.0").Pair(Revision("b2cb48dda625f6640b34d9ffb664533359ac8b91")),
			NewVersion("v1.0.0").Pair(Revision("bf85021c0405edbc4f3648b0603818d641674f72")),
			newDefaultBranch("master").Pair(Revision("bf85021c0405edbc4f3648b0603818d641674f72")),
			NewBranch("v1").Pair(Revision("e3777f683305eafca223aefe56b4e8ecf103f467")),
			NewBranch("v1.1").Pair(Revision("f1fbc520489a98306eb28c235204e39fa8a89c84")),
			NewBranch("v3").Pair(Revision("4a54adf81c75375d26d376459c00d5ff9b703e5e")),
		}
		for k, e := range evl {
			if !vlist[k].identical(e) {
				t.Errorf("version list was not what we expected:\n\t(GOT): %#v\n\t(WNT): %#v", vlist, evl)
				break
			}
		}
	}

	// recheck that rev is present, this time interacting with cache differently
	is, err = src.revisionPresentIn(Revision("30605f6ac35fcb075ad0bfa9296f90a7d891523e"))
	if err != nil {
		t.Errorf("Unexpected error while re-checking revision presence: %s", err)
	} else if !is {
		t.Errorf("Revision that should exist was not present on re-check")
	}
}

func testGopkginSourceInteractions(t *testing.T) {
	t.Parallel()

	// This test is slowish, skip it on -short
	if testing.Short() {
		t.Skip("Skipping gopkg.in source version fetching test in short mode")
	}
	requiresBins(t, "git")

	cpath, err := ioutil.TempDir("", "smcache")
	if err != nil {
		t.Errorf("Failed to create temp dir: %s", err)
	}
	defer func() {
		if err := os.RemoveAll(cpath); err != nil {
			t.Errorf("removeAll failed: %s", err)
		}
	}()
	os.Mkdir(filepath.Join(cpath, "sources"), 0777)

	tfunc := func(opath, n string, major uint64, evl []Version) {
		un := "https://" + opath
		u, err := url.Parse("https://" + n)
		if err != nil {
			t.Errorf("URL was bad, lolwut? errtext: %s", err)
			return
		}
		unstable := strings.HasSuffix(opath, gopkgUnstableSuffix)
		mb := maybeGopkginSource{
			opath:    opath,
			url:      u,
			major:    major,
			unstable: unstable,
		}

		ctx := context.Background()
		isrc, err := mb.try(ctx, cpath)
		if err != nil {
			t.Errorf("Unexpected error while setting up gopkginSource for test repo: %s", err)
			return
		}

		err = isrc.initLocal(ctx)
		if err != nil {
			t.Fatalf("Error on cloning git repo: %s", err)
		}

		src, ok := isrc.(*gopkginSource)
		if !ok {
			t.Errorf("Expected a gopkginSource, got a %T", isrc)
			return
		}

		if un != src.upstreamURL() {
			t.Errorf("Expected %s as source URL, got %s", un, src.upstreamURL())
		}
		if src.major != major {
			t.Errorf("Expected %v as major version filter on gopkginSource, got %v", major, src.major)
		}

		// check that an expected rev is present
		rev := evl[0].(PairedVersion).Revision()
		is, err := src.revisionPresentIn(rev)
		if err != nil {
			t.Errorf("Unexpected error while checking revision presence: %s", err)
		} else if !is {
			t.Errorf("Revision %s that should exist was not present", rev)
		}

		pvlist, err := src.listVersions(ctx)
		if err != nil {
			t.Errorf("Unexpected error getting version pairs from hg repo: %s", err)
		}

		vlist := hidePair(pvlist)
		if len(vlist) != len(evl) {
			t.Errorf("gopkgin test repo (%s) should've produced %v versions, got %v.\n%v", un, len(evl), len(vlist), vlist)
		} else {
			SortForUpgrade(vlist)
			if !reflect.DeepEqual(vlist, evl) {
				t.Errorf("Version list for %s was not what we expected:\n\t(GOT): %#v\n\t(WNT): %#v", un, vlist, evl)
			}
		}

		// Run again, this time to ensure cache outputs correctly
		pvlist, err = src.listVersions(ctx)
		if err != nil {
			t.Errorf("Unexpected error getting version pairs from hg repo: %s", err)
		}

		vlist = hidePair(pvlist)
		if len(vlist) != len(evl) {
			t.Errorf("gopkgin test repo should've produced %v versions, got %v", len(evl), len(vlist))
		} else {
			SortForUpgrade(vlist)
			if !reflect.DeepEqual(vlist, evl) {
				t.Errorf("Version list for %s was not what we expected:\n\t(GOT): %#v\n\t(WNT): %#v", un, vlist, evl)
			}
		}

		// recheck that rev is present, this time interacting with cache differently
		is, err = src.revisionPresentIn(rev)
		if err != nil {
			t.Errorf("Unexpected error while re-checking revision presence: %s", err)
		} else if !is {
			t.Errorf("Revision that should exist was not present on re-check")
		}
	}

	// simultaneously run for v1, v2, and v3 filters of the target repo
	wg := &sync.WaitGroup{}
	wg.Add(6)

	go func() {
		// Treat master as v0 when no other branches/tags exist that match gopkg.in's rules
		tfunc("gopkg.in/carolynvs/deptest-gopkgin-implicit-v0.v0", "github.com/carolynvs/deptest-gopkgin-implicit-v0", 0, []Version{
			newDefaultBranch("notmaster").Pair(Revision("94ee631b9833cd805d15f50a52e0533124ec0292")),
		})
		wg.Done()
	}()

	go func() {
		// Use the existing v0 branch for v0, not master
		tfunc("gopkg.in/carolynvs/deptest-gopkgin-explicit-v0.v0", "github.com/carolynvs/deptest-gopkgin-explicit-v0", 0, []Version{
			newDefaultBranch("v0").Pair(Revision("ec73e84554fb28f08dba630e48dbec868e77f734")),
		})
		wg.Done()
	}()

	go func() {
		tfunc("gopkg.in/sdboyer/gpkt.v1", "github.com/sdboyer/gpkt", 1, []Version{
			NewVersion("v1.1.0").Pair(Revision("b2cb48dda625f6640b34d9ffb664533359ac8b91")),
			NewVersion("v1.0.0").Pair(Revision("bf85021c0405edbc4f3648b0603818d641674f72")),
			newDefaultBranch("v1.1").Pair(Revision("f1fbc520489a98306eb28c235204e39fa8a89c84")),
			NewBranch("v1").Pair(Revision("e3777f683305eafca223aefe56b4e8ecf103f467")),
		})
		wg.Done()
	}()

	go func() {
		tfunc("gopkg.in/sdboyer/gpkt.v2", "github.com/sdboyer/gpkt", 2, []Version{
			NewVersion("v2.0.0").Pair(Revision("4a54adf81c75375d26d376459c00d5ff9b703e5e")),
		})
		wg.Done()
	}()

	go func() {
		tfunc("gopkg.in/sdboyer/gpkt.v3", "github.com/sdboyer/gpkt", 3, []Version{
			newDefaultBranch("v3").Pair(Revision("4a54adf81c75375d26d376459c00d5ff9b703e5e")),
		})
		wg.Done()
	}()

	go func() {
		tfunc("github.com/sdboyer/gpkt2.v1-unstable", "github.com/sdboyer/gpkt2", 1, []Version{
			newDefaultBranch("v1-unstable").Pair(Revision("24de0be8f4a0b8a44321562117749b257bfcef69")),
		})
		wg.Done()
	}()

	wg.Wait()
}

func testBzrSourceInteractions(t *testing.T) {
	t.Parallel()

	// This test is quite slow (ugh bzr), so skip it on -short
	if testing.Short() {
		t.Skip("Skipping bzr source version fetching test in short mode")
	}
	if runtime.GOOS == "windows" {
		// TODO bzr on Windows is sometimes weirdly reporting different
		// "revision-id" (with mention of git), and it's breaking tests. Maybe
		// this also breaks our model of bzr on Windows; maybe it breaks our
		// model of bzr in general. But use of bzr is rare and dwindling, so for
		// now it's least harmful to turn off the test on Windows, as the
		// alternative is a DEEP dive and possible refactor.
		t.Skip("TODO: Windows bzr reporting of underlying object ids is confusing")
	}
	requiresBins(t, "bzr")

	cpath, err := ioutil.TempDir("", "smcache")
	if err != nil {
		t.Errorf("Failed to create temp dir: %s", err)
	}
	defer func() {
		if err := os.RemoveAll(cpath); err != nil {
			t.Errorf("removeAll failed: %s", err)
		}
	}()

	n := "launchpad.net/govcstestbzrrepo"
	un := "https://" + n
	u, err := url.Parse(un)
	if err != nil {
		t.Fatalf("Error parsing URL %s: %s", un, err)
	}
	mb := maybeBzrSource{
		url: u,
	}

	ctx := context.Background()
	isrc, err := mb.try(ctx, cpath)
	if err != nil {
		t.Fatalf("Unexpected error while setting up bzrSource for test repo: %s", err)
	}

	err = isrc.initLocal(ctx)
	if err != nil {
		t.Fatalf("Error on cloning bzr repo: %s", err)
	}

	src, ok := isrc.(*bzrSource)
	if !ok {
		t.Fatalf("Expected a bzrSource, got a %T", isrc)
	}

	if un != src.upstreamURL() {
		t.Errorf("Expected %s as source URL, got %s", un, src.upstreamURL())
	}
	evl := []Version{
		NewVersion("1.0.0").Pair(Revision("matt@mattfarina.com-20150731135137-pbphasfppmygpl68")),
		newDefaultBranch("(default)").Pair(Revision("matt@mattfarina.com-20150731135137-pbphasfppmygpl68")),
	}

	// check that an expected rev is present
	is, err := src.revisionPresentIn(Revision("matt@mattfarina.com-20150731135137-pbphasfppmygpl68"))
	if err != nil {
		t.Errorf("Unexpected error while checking revision presence: %s", err)
	} else if !is {
		t.Errorf("Revision that should exist was not present")
	}

	pvlist, err := src.listVersions(ctx)
	if err != nil {
		t.Errorf("Unexpected error getting version pairs from bzr repo: %s", err)
	}

	vlist := hidePair(pvlist)
	if len(vlist) != 2 {
		t.Errorf("bzr test repo should've produced two versions, got %v", len(vlist))
	} else {
		SortForUpgrade(vlist)
		if !reflect.DeepEqual(vlist, evl) {
			t.Errorf("bzr version list was not what we expected:\n\t(GOT): %s\n\t(WNT): %s", vlist, evl)
		}
	}

	// Run again, this time to ensure cache outputs correctly
	pvlist, err = src.listVersions(ctx)
	if err != nil {
		t.Errorf("Unexpected error getting version pairs from bzr repo: %s", err)
	}

	vlist = hidePair(pvlist)
	if len(vlist) != 2 {
		t.Errorf("bzr test repo should've produced two versions, got %v", len(vlist))
	} else {
		SortForUpgrade(vlist)
		if !reflect.DeepEqual(vlist, evl) {
			t.Errorf("bzr version list was not what we expected:\n\t(GOT): %s\n\t(WNT): %s", vlist, evl)
		}
	}

	// recheck that rev is present, this time interacting with cache differently
	is, err = src.revisionPresentIn(Revision("matt@mattfarina.com-20150731135137-pbphasfppmygpl68"))
	if err != nil {
		t.Errorf("Unexpected error while re-checking revision presence: %s", err)
	} else if !is {
		t.Errorf("Revision that should exist was not present on re-check")
	}
}

func testHgSourceInteractions(t *testing.T) {
	t.Parallel()

	// This test is slow, so skip it on -short
	if testing.Short() {
		t.Skip("Skipping hg source version fetching test in short mode")
	}
	requiresBins(t, "hg")

	cpath, err := ioutil.TempDir("", "smcache")
	if err != nil {
		t.Errorf("Failed to create temp dir: %s", err)
	}
	defer func() {
		if err := os.RemoveAll(cpath); err != nil {
			t.Errorf("removeAll failed: %s", err)
		}
	}()

	tfunc := func(n string, evl []Version) {
		un := "https://" + n
		u, err := url.Parse(un)
		if err != nil {
			t.Errorf("URL was bad, lolwut? errtext: %s", err)
			return
		}
		mb := maybeHgSource{
			url: u,
		}

		ctx := context.Background()
		isrc, err := mb.try(ctx, cpath)
		if err != nil {
			t.Errorf("Unexpected error while setting up hgSource for test repo: %s", err)
			return
		}

		err = isrc.initLocal(ctx)
		if err != nil {
			t.Errorf("Error on cloning hg repo: %s", err)
			return
		}

		src, ok := isrc.(*hgSource)
		if !ok {
			t.Errorf("Expected a hgSource, got a %T", isrc)
			return
		}

		if un != src.upstreamURL() {
			t.Errorf("Expected %s as source URL, got %s", un, src.upstreamURL())
		}

		// check that an expected rev is present
		is, err := src.revisionPresentIn(Revision("103d1bddef2199c80aad7c42041223083d613ef9"))
		if err != nil {
			t.Errorf("Unexpected error while checking revision presence: %s", err)
		} else if !is {
			t.Errorf("Revision that should exist was not present")
		}

		pvlist, err := src.listVersions(ctx)
		if err != nil {
			t.Errorf("Unexpected error getting version pairs from hg repo: %s", err)
		}

		vlist := hidePair(pvlist)
		if len(vlist) != len(evl) {
			t.Errorf("hg test repo should've produced %v versions, got %v", len(evl), len(vlist))
		} else {
			SortForUpgrade(vlist)

			for k, e := range evl {
				if !vlist[k].identical(e) {
					t.Errorf("version list was not what we expected:\n\t(GOT): %#v\n\t(WNT): %#v", vlist, evl)
					break
				}
			}
		}

		// Run again, this time to ensure cache outputs correctly
		pvlist, err = src.listVersions(ctx)
		if err != nil {
			t.Errorf("Unexpected error getting version pairs from hg repo: %s", err)
		}

		vlist = hidePair(pvlist)
		if len(vlist) != len(evl) {
			t.Errorf("hg test repo should've produced %v versions, got %v", len(evl), len(vlist))
		} else {
			SortForUpgrade(vlist)
			for k, e := range evl {
				if !vlist[k].identical(e) {
					t.Errorf("version list was not what we expected:\n\t(GOT): %#v\n\t(WNT): %#v", vlist, evl)
					break
				}
			}
		}

		// recheck that rev is present, this time interacting with cache differently
		is, err = src.revisionPresentIn(Revision("103d1bddef2199c80aad7c42041223083d613ef9"))
		if err != nil {
			t.Errorf("Unexpected error while re-checking revision presence: %s", err)
		} else if !is {
			t.Errorf("Revision that should exist was not present on re-check")
		}
	}

	// simultaneously run for both the repo with and without the magic bookmark
	donech := make(chan struct{})
	go func() {
		tfunc("bitbucket.org/sdboyer/withbm", []Version{
			NewVersion("v1.0.0").Pair(Revision("aa110802a0c64195d0a6c375c9f66668827c90b4")),
			newDefaultBranch("@").Pair(Revision("b10d05d581e5401f383e48ccfeb84b48fde99d06")),
			NewBranch("another").Pair(Revision("b10d05d581e5401f383e48ccfeb84b48fde99d06")),
			NewBranch("default").Pair(Revision("3d466f437f6616da594bbab6446cc1cb4328d1bb")),
			NewBranch("newbranch").Pair(Revision("5e2a01be9aee942098e44590ae545c7143da9675")),
		})
		close(donech)
	}()

	tfunc("bitbucket.org/sdboyer/nobm", []Version{
		NewVersion("v1.0.0").Pair(Revision("aa110802a0c64195d0a6c375c9f66668827c90b4")),
		newDefaultBranch("default").Pair(Revision("3d466f437f6616da594bbab6446cc1cb4328d1bb")),
		NewBranch("another").Pair(Revision("b10d05d581e5401f383e48ccfeb84b48fde99d06")),
		NewBranch("newbranch").Pair(Revision("5e2a01be9aee942098e44590ae545c7143da9675")),
	})

	<-donech
}

func TestGitSourceListVersionsNoHEAD(t *testing.T) {
	// t.Parallel()

	requiresBins(t, "git")

	h := test.NewHelper(t)
	defer h.Cleanup()
	h.TempDir("smcache")
	cpath := h.Path("smcache")
	os.Mkdir(filepath.Join(cpath, "sources"), 0777)

	h.TempDir("repo")
	repoPath := h.Path("repo")

	// Create test repo with a single commit on the master branch
	h.RunGit(repoPath, "init")
	h.RunGit(repoPath, "config", "--local", "user.email", "test@example.com")
	h.RunGit(repoPath, "config", "--local", "user.name", "Test author")
	h.RunGit(repoPath, "commit", "--allow-empty", `--message="Initial commit"`)

	// Make HEAD point at a nonexistent branch (deleting it is not allowed)
	// The `git ls-remote` that listVersions() calls will not return a HEAD ref
	// because it points at a nonexistent branch
	h.RunGit(repoPath, "symbolic-ref", "HEAD", "refs/heads/nonexistent")

	un := "file://" + filepath.ToSlash(repoPath)
	u, err := url.Parse(un)
	if err != nil {
		t.Fatalf("Error parsing URL %s: %s", un, err)
	}
	mb := maybeGitSource{u}

	ctx := context.Background()
	isrc, err := mb.try(ctx, cpath)
	if err != nil {
		t.Fatalf("Unexpected error while setting up gitSource for test repo: %s", err)
	}

	err = isrc.initLocal(ctx)
	if err != nil {
		t.Fatalf("Error on cloning git repo: %s", err)
	}

	src, ok := isrc.(*gitSource)
	if !ok {
		t.Fatalf("Expected a gitSource, got a %T", isrc)
	}

	pvlist, err := src.listVersions(ctx)
	if err != nil {
		t.Fatalf("Unexpected error getting version pairs from git repo: %s", err)
	}

	if len(pvlist) != 1 {
		t.Errorf("Unexpected version pair length:\n\t(GOT): %d\n\t(WNT): %d", len(pvlist), 1)
	}
}

func TestGitSourceListVersionsNoDupes(t *testing.T) {
	// t.Parallel()

	// This test is slowish, skip it on -short
	if testing.Short() {
		t.Skip("Skipping git source version fetching test in short mode")
	}
	requiresBins(t, "git")

	cpath, err := ioutil.TempDir("", "smcache")
	if err != nil {
		t.Errorf("Failed to create temp dir: %s", err)
	}
	defer func() {
		if err := os.RemoveAll(cpath); err != nil {
			t.Errorf("removeAll failed: %s", err)
		}
	}()
	os.Mkdir(filepath.Join(cpath, "sources"), 0777)

	n := "github.com/carolynvs/deptest-importers"
	un := "https://" + n
	u, err := url.Parse(un)
	if err != nil {
		t.Fatalf("Error parsing URL %s: %s", un, err)
	}
	mb := maybeGitSource{
		url: u,
	}

	ctx := context.Background()
	src, err := mb.try(ctx, cpath)
	if err != nil {
		t.Fatalf("Unexpected error while setting up gitSource for test repo: %s", err)
	}

	err = src.initLocal(ctx)
	if err != nil {
		t.Fatalf("Error on cloning git repo: %s", err)
	}

	pvlist, err := src.listVersions(ctx)
	if err != nil {
		t.Fatalf("Unexpected error getting version pairs from git repo: %s", err)
	}

	for i := range pvlist {
		pv1 := pvlist[i]
		uv1 := pv1.Unpair()
		for j := range pvlist {
			if i == j {
				continue
			}
			pv2 := pvlist[j]
			uv2 := pv2.Unpair()
			if uv1 == uv2 {
				t.Errorf("duplicate version pair mapping from %#v to both %q and %q", uv1, pv1.Revision(), pv2.Revision())
			}
		}
	}
}

func TestGitSourceAdaptiveCleanup(t *testing.T) {
	// t.Parallel()

	// This test is slowish, skip it on -short
	if testing.Short() {
		t.Skip("Skipping git adaptive failure recovery test in short mode")
	}
	requiresBins(t, "git")

	cpath, err := ioutil.TempDir("", "smcache")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %s", err)
	}

	var sm *SourceMgr
	mkSM := func() {
		// If sm is already set, make sure it's released, then create a new one.
		if sm != nil {
			sm.Release()
		}

		var err error
		sm, err = NewSourceManager(SourceManagerConfig{
			Cachedir: cpath,
			Logger:   log.New(test.Writer{TB: t}, "", 0),
		})
		if err != nil {
			t.Fatalf("Unexpected error on SourceManager creation: %s", err)
		}
	}

	mkSM()
	id := mkPI("github.com/sdboyer/gpkt")
	err = sm.SyncSourceFor(id)
	if err != nil {
		t.Fatal(err)
	}

	repodir := filepath.Join(sm.cachedir, "sources", "https---github.com-sdboyer-gpkt")
	if _, err := os.Stat(repodir); err != nil {
		if os.IsNotExist(err) {
			t.Fatalf("expected location for repodir did not exist: %q", repodir)
		} else {
			t.Fatal(err)
		}
	}

	// Create a file that git will see as untracked.
	untrackedPath := filepath.Join(repodir, "untrackedfile")
	err = ioutil.WriteFile(untrackedPath, []byte("foo"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	mkSM()
	err = sm.SyncSourceFor(id)
	if err != nil {
		t.Fatalf("choked after adding dummy file: %q", err)
	}

	if _, err := os.Stat(untrackedPath); err == nil {
		t.Fatal("untracked file still existed after cleanup should've been triggered")
	}

	// Remove a file that we know exists, which `git status` checks should catch.
	readmePath := filepath.Join(repodir, "README.md")
	os.Remove(readmePath)

	mkSM()
	err = sm.SyncSourceFor(id)
	if err != nil {
		t.Fatalf("choked after removing known file: %q", err)
	}

	if _, err := os.Stat(readmePath); err != nil {
		t.Fatal("README was still absent after cleanup should've been triggered")
	}

	// Remove .git/objects directory, which should make git bite it.
	err = os.RemoveAll(filepath.Join(repodir, ".git", "objects"))
	if err != nil {
		t.Fatal(err)
	}

	mkSM()
	err = sm.SyncSourceFor(id)
	if err != nil {
		t.Fatalf("choked after removing .git/objects directory: %q", err)
	}

	sm.Release()
	os.RemoveAll(cpath)
}

func Test_bzrSource_exportRevisionTo_removeVcsFiles(t *testing.T) {
	t.Parallel()

	// This test is slow, so skip it on -short
	if testing.Short() {
		t.Skip("Skipping hg source version fetching test in short mode")
	}
	if runtime.GOOS == "windows" {
		// TODO see todo in TestBzrSourceInteractions
		t.Skip("TODO: Windows bzr reporting of underlying object ids is confusing")
	}
	requiresBins(t, "bzr")

	h := test.NewHelper(t)
	defer h.Cleanup()
	h.TempDir("smcache")
	cpath := h.Path("smcache")
	repoPath := filepath.Join(h.Path("."), "repo")

	rev := Revision("matt@mattfarina.com-20150731135137-pbphasfppmygpl68")
	n := "launchpad.net/govcstestbzrrepo"
	un := "https://" + n
	u, err := url.Parse(un)
	if err != nil {
		t.Errorf("URL was bad, lolwut? errtext: %s", err)
		return
	}
	mb := maybeBzrSource{u}

	ctx := context.Background()
	isrc, err := mb.try(ctx, cpath)
	if err != nil {
		t.Fatalf("unexpected error while setting up hgSource for test repo: %s", err)
	}

	err = isrc.initLocal(ctx)
	if err != nil {
		t.Fatalf("Error on cloning bzr repo: %s", err)
	}

	src, ok := isrc.(*bzrSource)
	if !ok {
		t.Fatalf("expected a bzrSource, got a %T", isrc)
	}

	if err := src.exportRevisionTo(ctx, rev, repoPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = os.Stat(filepath.Join(repoPath, ".bzr"))
	if err == nil {
		t.Fatal("expected .bzr/ to not exists")
	} else if !os.IsNotExist(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func Test_hgSource_exportRevisionTo_removeVcsFiles(t *testing.T) {
	t.Parallel()

	// This test is slow, so skip it on -short
	if testing.Short() {
		t.Skip("Skipping hg source version fetching test in short mode")
	}
	requiresBins(t, "hg")

	h := test.NewHelper(t)
	defer h.Cleanup()
	h.TempDir("smcache")
	cpath := h.Path("smcache")
	repoPath := filepath.Join(h.Path("."), "repo")

	rev := Revision("6f55e1f03d91f8a7cce35d1968eb60a2352e4d59")
	n := "bitbucket.org/golang-dep/dep-test"
	un := "https://" + n
	u, err := url.Parse(un)
	if err != nil {
		t.Errorf("URL was bad, lolwut? errtext: %s", err)
		return
	}
	mb := maybeHgSource{u}

	ctx := context.Background()
	isrc, err := mb.try(ctx, cpath)
	if err != nil {
		t.Fatalf("unexpected error while setting up hgSource for test repo: %s", err)
	}

	err = isrc.initLocal(ctx)
	if err != nil {
		t.Fatalf("Error on cloning hg repo: %s", err)
	}

	src, ok := isrc.(*hgSource)
	if !ok {
		t.Fatalf("expected a hgSource, got a %T", isrc)
	}

	if err := src.exportRevisionTo(ctx, rev, repoPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = os.Stat(filepath.Join(repoPath, ".hg"))
	if err == nil {
		t.Fatal("expected .hg/ to not exists")
	} else if !os.IsNotExist(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Fail a test if the specified binaries aren't installed.
func requiresBins(t *testing.T, bins ...string) {
	for _, b := range bins {
		_, err := exec.LookPath(b)
		if err != nil {
			t.Fatalf("%s is not installed", b)
		}
	}
}
