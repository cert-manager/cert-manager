// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dep

import (
	"path/filepath"
	"testing"

	"github.com/golang/dep/internal/test"
)

func TestAnalyzerDeriveManifestAndLock(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir("dep")
	golden := filepath.Join("analyzer", ManifestName)
	want := h.GetTestFileString(golden)
	h.TempCopy(filepath.Join("dep", ManifestName), golden)

	a := Analyzer{}

	m, l, err := a.DeriveManifestAndLock(h.Path("dep"), "my/fake/project")
	if err != nil {
		t.Fatal(err)
	}

	got, err := m.(*Manifest).MarshalTOML()
	if err != nil {
		t.Fatal(err)
	}

	if want != string(got) {
		if *test.UpdateGolden {
			if err := h.WriteTestFile(golden, string(got)); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Fatalf("(WNT):\n%s\n(GOT):\n%s", want, string(got))
		}
	}

	if l != nil {
		t.Fatalf("expected lock to be nil, got: %#v", l)
	}
}

func TestAnalyzerDeriveManifestAndLockDoesNotExist(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir("dep")

	a := Analyzer{}

	m, l, err := a.DeriveManifestAndLock(h.Path("dep"), "my/fake/project")
	if m != nil || l != nil || err != nil {
		t.Fatalf("expected manifest & lock & err to be nil: m -> %#v l -> %#v err-> %#v", m, l, err)
	}
}

func TestAnalyzerDeriveManifestAndLockCannotOpen(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir("dep")

	// Simulate an inaccessible manifest file.
	h.TempFile(filepath.Join("dep", ManifestName), "")
	closer, err := makeUnreadable(filepath.Join(h.Path("dep"), ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()

	a := Analyzer{}

	// Verify that the solver rejects the manifest, rather than treating it as
	// offering no constraints.
	m, l, err := a.DeriveManifestAndLock(h.Path("dep"), "my/fake/project")
	if m != nil || l != nil || err == nil {
		t.Fatalf("expected manifest & lock to be nil, err to be not nil: m -> %#v l -> %#v err -> %#v", m, l, err)
	}
}

func TestAnalyzerDeriveManifestAndLockInvalidManifest(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir("dep")

	// Create a manifest with invalid contents
	h.TempFile(filepath.Join("dep", ManifestName), "invalid manifest")

	a := Analyzer{}

	m, l, err := a.DeriveManifestAndLock(h.Path("dep"), "my/fake/project")
	if m != nil || l != nil || err == nil {
		t.Fatalf("expected manifest & lock & err to be nil: m -> %#v l -> %#v err-> %#v", m, l, err)
	}
}

func TestAnalyzerInfo(t *testing.T) {
	a := Analyzer{}

	info := a.Info()

	if info.Name != "dep" || info.Version != 1 {
		t.Fatalf("expected name to be 'dep' and version to be 1: name -> %q vers -> %d", info.Name, info.Version)
	}
}
