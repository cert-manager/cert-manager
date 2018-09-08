// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/golang/dep/internal/test"
)

var basicResult solution

func pi(n string) ProjectIdentifier {
	return ProjectIdentifier{
		ProjectRoot: ProjectRoot(n),
	}
}

func init() {
	basicResult = solution{
		att: 1,
		p: []LockedProject{
			pa2lp(atom{
				id: pi("github.com/sdboyer/testrepo"),
				v:  NewBranch("master").Pair(Revision("4d59fb584b15a94d7401e356d2875c472d76ef45")),
			}, nil),
			pa2lp(atom{
				id: pi("github.com/Masterminds/VCSTestRepo"),
				v:  NewVersion("1.0.0").Pair(Revision("30605f6ac35fcb075ad0bfa9296f90a7d891523e")),
			}, nil),
		},
	}
	basicResult.analyzerInfo = (naiveAnalyzer{}).Info()
}

func testWriteDepTree(t *testing.T) {
	t.Parallel()

	// This test is a bit slow, skip it on -short
	if testing.Short() {
		t.Skip("Skipping dep tree writing test in short mode")
	}
	requiresBins(t, "git", "hg", "bzr")

	tmp, err := ioutil.TempDir("", "writetree")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %s", err)
	}
	defer os.RemoveAll(tmp)

	// bzr appears to not be consistent across...versions? platforms? (who
	// knows) with respect to its internal object identifiers. This has tanked
	// our Windows tests, because it's sniffing for this one revision, but the
	// rev is reported differently on some Windows versions, with some versions
	// of bzr. It's especially vexing because these tests worked fine for years,
	// then abruptly broke for no obvious reason.
	var bzrv Version = NewVersion("1.0.0")
	if runtime.GOOS != "windows" {
		bzrv = bzrv.(semVersion).Pair(Revision("matt@mattfarina.com-20150731135137-pbphasfppmygpl68"))
	}

	r := solution{
		att: 1,
		p: []LockedProject{
			pa2lp(atom{
				id: pi("github.com/sdboyer/testrepo"),
				v:  NewBranch("master").Pair(Revision("4d59fb584b15a94d7401e356d2875c472d76ef45")),
			}, nil),
			pa2lp(atom{
				id: pi("launchpad.net/govcstestbzrrepo"),
				v:  bzrv,
			}, nil),
			pa2lp(atom{
				id: pi("bitbucket.org/sdboyer/withbm"),
				v:  NewVersion("v1.0.0").Pair(Revision("aa110802a0c64195d0a6c375c9f66668827c90b4")),
			}, nil),
		},
	}

	sm, clean := mkNaiveSM(t)
	defer clean()

	// Trigger simultaneous fetch of all three to speed up test execution time
	for _, p := range r.p {
		go func(pi ProjectIdentifier) {
			sm.SyncSourceFor(pi)
		}(p.Ident())
	}

	// nil lock/result should err immediately
	err = WriteDepTree(tmp, nil, sm, defaultCascadingPruneOptions(), nil)
	if err == nil {
		t.Errorf("Should error if nil lock is passed to WriteDepTree")
	}

	err = WriteDepTree(tmp, r, sm, defaultCascadingPruneOptions(), nil)
	if err != nil {
		t.Errorf("Unexpected error while creating vendor tree: %s", err)
	}

	if _, err = os.Stat(filepath.Join(tmp, "github.com", "sdboyer", "testrepo")); err != nil {
		t.Errorf("Directory for github.com/sdboyer/testrepo does not exist")
	}
	if _, err = os.Stat(filepath.Join(tmp, "launchpad.net", "govcstestbzrrepo")); err != nil {
		t.Errorf("Directory for launchpad.net/govcstestbzrrepo does not exist")
	}
	if _, err = os.Stat(filepath.Join(tmp, "bitbucket.org", "sdboyer", "withbm")); err != nil {
		t.Errorf("Directory for bitbucket.org/sdboyer/withbm does not exist")
	}
}

func BenchmarkCreateVendorTree(b *testing.B) {
	// We're fs-bound here, so restrict to single parallelism
	b.SetParallelism(1)

	r := basicResult
	tmp := path.Join(os.TempDir(), "vsolvtest")

	clean := true
	sm, err := NewSourceManager(SourceManagerConfig{
		Cachedir: path.Join(tmp, "cache"),
		Logger:   log.New(test.Writer{TB: b}, "", 0),
	})
	if err != nil {
		b.Fatalf("failed to create SourceManager: %q", err)
	}

	// Prefetch the projects before timer starts
	for _, lp := range r.p {
		err := sm.SyncSourceFor(lp.Ident())
		if err != nil {
			b.Errorf("failed getting project info during prefetch: %s", err)
			clean = false
		}
	}

	if clean {
		b.ResetTimer()
		b.StopTimer()
		exp := path.Join(tmp, "export")
		for i := 0; i < b.N; i++ {
			// Order the loop this way to make it easy to disable final cleanup, to
			// ease manual inspection
			os.RemoveAll(exp)
			b.StartTimer()
			err = WriteDepTree(exp, r, sm, defaultCascadingPruneOptions(), nil)
			b.StopTimer()
			if err != nil {
				b.Errorf("unexpected error after %v iterations: %s", i, err)
				break
			}
		}
	}

	sm.Release()
	os.RemoveAll(tmp) // comment this to leave temp dir behind for inspection
}
