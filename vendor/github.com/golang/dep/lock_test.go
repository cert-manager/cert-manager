// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dep

import (
	"reflect"
	"strings"
	"testing"

	"github.com/golang/dep/gps"
	"github.com/golang/dep/gps/verify"
	"github.com/golang/dep/internal/test"
)

func TestReadLock(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	golden := "lock/golden0.toml"
	g0f := h.GetTestFile(golden)
	defer g0f.Close()
	got, err := readLock(g0f)
	if err != nil {
		t.Fatalf("Should have read Lock correctly, but got err %q", err)
	}

	want := &Lock{
		SolveMeta: SolveMeta{InputImports: []string{}},
		P: []gps.LockedProject{
			verify.VerifiableProject{
				LockedProject: gps.NewLockedProject(
					gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/golang/dep")},
					gps.NewBranch("master").Pair(gps.Revision("d05d5aca9f895d19e9265839bffeadd74a2d2ecb")),
					[]string{"."},
				),
				PruneOpts: gps.PruneOptions(1),
				Digest: verify.VersionedDigest{
					HashVersion: verify.HashVersion,
					Digest:      []byte("foo"),
				},
			},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Error("Valid lock did not parse as expected")
	}

	golden = "lock/golden1.toml"
	g1f := h.GetTestFile(golden)
	defer g1f.Close()
	got, err = readLock(g1f)
	if err != nil {
		t.Fatalf("Should have read Lock correctly, but got err %q", err)
	}

	want = &Lock{
		SolveMeta: SolveMeta{InputImports: []string{}},
		P: []gps.LockedProject{
			verify.VerifiableProject{
				LockedProject: gps.NewLockedProject(
					gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/golang/dep")},
					gps.NewVersion("0.12.2").Pair(gps.Revision("d05d5aca9f895d19e9265839bffeadd74a2d2ecb")),
					[]string{"."},
				),
				PruneOpts: gps.PruneOptions(15),
				Digest: verify.VersionedDigest{
					HashVersion: verify.HashVersion,
					Digest:      []byte("foo"),
				},
			},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Error("Valid lock did not parse as expected")
	}
}

func TestWriteLock(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	golden := "lock/golden0.toml"
	want := h.GetTestFileString(golden)
	l := &Lock{
		P: []gps.LockedProject{
			verify.VerifiableProject{
				LockedProject: gps.NewLockedProject(
					gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/golang/dep")},
					gps.NewBranch("master").Pair(gps.Revision("d05d5aca9f895d19e9265839bffeadd74a2d2ecb")),
					[]string{"."},
				),
				PruneOpts: gps.PruneOptions(1),
				Digest: verify.VersionedDigest{
					HashVersion: verify.HashVersion,
					Digest:      []byte("foo"),
				},
			},
		},
	}

	got, err := l.MarshalTOML()
	if err != nil {
		t.Fatalf("Error while marshaling valid lock to TOML: %q", err)
	}

	if string(got) != want {
		if *test.UpdateGolden {
			if err = h.WriteTestFile(golden, string(got)); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Errorf("Valid lock did not marshal to TOML as expected:\n\t(GOT): %s\n\t(WNT): %s", string(got), want)
		}
	}

	golden = "lock/golden1.toml"
	want = h.GetTestFileString(golden)
	l = &Lock{
		P: []gps.LockedProject{
			verify.VerifiableProject{
				LockedProject: gps.NewLockedProject(
					gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/golang/dep")},
					gps.NewVersion("0.12.2").Pair(gps.Revision("d05d5aca9f895d19e9265839bffeadd74a2d2ecb")),
					[]string{"."},
				),
				PruneOpts: gps.PruneOptions(15),
				Digest: verify.VersionedDigest{
					HashVersion: verify.HashVersion,
					Digest:      []byte("foo"),
				},
			},
		},
	}

	got, err = l.MarshalTOML()
	if err != nil {
		t.Fatalf("Error while marshaling valid lock to TOML: %q", err)
	}

	if string(got) != want {
		if *test.UpdateGolden {
			if err = h.WriteTestFile(golden, string(got)); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Errorf("Valid lock did not marshal to TOML as expected:\n\t(GOT): %s\n\t(WNT): %s", string(got), want)
		}
	}
}

func TestReadLockErrors(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()
	var err error

	tests := []struct {
		name string
		file string
	}{
		{"specified both", "lock/error0.toml"},
		{"odd length", "lock/error1.toml"},
		{"no branch or version", "lock/error2.toml"},
	}

	for _, tst := range tests {
		lf := h.GetTestFile(tst.file)
		defer lf.Close()
		_, err = readLock(lf)
		if err == nil {
			t.Errorf("Reading lock with %s should have caused error, but did not", tst.name)
		} else if !strings.Contains(err.Error(), tst.name) {
			t.Errorf("Unexpected error %q; expected %s error", err, tst.name)
		}
	}
}
