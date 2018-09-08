// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/golang/dep/internal/test"
)

func TestCascadingPruneOptions(t *testing.T) {
	cases := []struct {
		name    string
		co      CascadingPruneOptions
		results map[ProjectRoot]PruneOptions
	}{
		{
			name: "all empty values",
			co: CascadingPruneOptions{
				DefaultOptions: PruneNestedVendorDirs,
				PerProjectOptions: map[ProjectRoot]PruneOptionSet{
					ProjectRoot("github.com/golang/dep"): {},
				},
			},
			results: map[ProjectRoot]PruneOptions{
				ProjectRoot("github.com/golang/dep"): PruneNestedVendorDirs,
			},
		},
		{
			name: "all overridden",
			co: CascadingPruneOptions{
				DefaultOptions: PruneNestedVendorDirs,
				PerProjectOptions: map[ProjectRoot]PruneOptionSet{
					ProjectRoot("github.com/golang/dep"): {
						NestedVendor:   2,
						UnusedPackages: 1,
						NonGoFiles:     1,
						GoTests:        1,
					},
				},
			},
			results: map[ProjectRoot]PruneOptions{
				ProjectRoot("github.com/golang/dep"): PruneUnusedPackages | PruneNonGoFiles | PruneGoTestFiles,
			},
		},
		{
			name: "all redundant",
			co: CascadingPruneOptions{
				DefaultOptions: PruneNestedVendorDirs,
				PerProjectOptions: map[ProjectRoot]PruneOptionSet{
					ProjectRoot("github.com/golang/dep"): {
						NestedVendor:   1,
						UnusedPackages: 2,
						NonGoFiles:     2,
						GoTests:        2,
					},
				},
			},
			results: map[ProjectRoot]PruneOptions{
				ProjectRoot("github.com/golang/dep"): PruneNestedVendorDirs,
			},
		},
		{
			name: "multiple projects, all combos",
			co: CascadingPruneOptions{
				DefaultOptions: PruneNestedVendorDirs,
				PerProjectOptions: map[ProjectRoot]PruneOptionSet{
					ProjectRoot("github.com/golang/dep"): {
						NestedVendor:   1,
						UnusedPackages: 2,
						NonGoFiles:     2,
						GoTests:        2,
					},
					ProjectRoot("github.com/other/one"): {
						NestedVendor:   2,
						UnusedPackages: 1,
						NonGoFiles:     1,
						GoTests:        1,
					},
				},
			},
			results: map[ProjectRoot]PruneOptions{
				ProjectRoot("github.com/golang/dep"): PruneNestedVendorDirs,
				ProjectRoot("github.com/other/one"):  PruneUnusedPackages | PruneNonGoFiles | PruneGoTestFiles,
				ProjectRoot("not/there"):             PruneNestedVendorDirs,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for pr, wanted := range c.results {
				if c.co.PruneOptionsFor(pr) != wanted {
					t.Fatalf("did not get expected final PruneOptions value from cascade:\n\t(GOT): %d\n\t(WNT): %d", c.co.PruneOptionsFor(pr), wanted)
				}

			}
		})
	}
}

func TestPruneProject(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	pr := "github.com/project/repository"
	h.TempDir(pr)

	baseDir := h.Path(".")
	lp := lockedProject{
		pi: ProjectIdentifier{
			ProjectRoot: ProjectRoot(pr),
		},
		pkgs: []string{},
	}

	options := PruneNestedVendorDirs | PruneNonGoFiles | PruneGoTestFiles | PruneUnusedPackages

	err := PruneProject(baseDir, lp, options)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPruneUnusedPackages(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir(".")

	pr := "github.com/sample/repository"
	pi := ProjectIdentifier{ProjectRoot: ProjectRoot(pr)}

	testcases := []struct {
		name string
		lp   LockedProject
		fs   fsTestCase
		err  bool
	}{
		{
			"one-package",
			lockedProject{
				pi: pi,
				pkgs: []string{
					".",
				},
			},
			fsTestCase{
				before: filesystemState{
					files: []string{
						"main.go",
					},
				},
				after: filesystemState{
					files: []string{
						"main.go",
					},
				},
			},
			false,
		},
		{
			"nested-package",
			lockedProject{
				pi: pi,
				pkgs: []string{
					"pkg",
				},
			},
			fsTestCase{
				before: filesystemState{
					dirs: []string{
						"pkg",
					},
					files: []string{
						"main.go",
						"pkg/main.go",
					},
				},
				after: filesystemState{
					dirs: []string{
						"pkg",
					},
					files: []string{
						"pkg/main.go",
					},
				},
			},
			false,
		},
		{
			"complex-project",
			lockedProject{
				pi: pi,
				pkgs: []string{
					"pkg",
					"pkg/nestedpkg/otherpkg",
				},
			},
			fsTestCase{
				before: filesystemState{
					dirs: []string{
						"pkg",
						"pkg/nestedpkg",
						"pkg/nestedpkg/otherpkg",
					},
					files: []string{
						"main.go",
						"COPYING",
						"pkg/main.go",
						"pkg/nestedpkg/main.go",
						"pkg/nestedpkg/legal.go",
						"pkg/nestedpkg/PATENT.md",
						"pkg/nestedpkg/otherpkg/main.go",
					},
				},
				after: filesystemState{
					dirs: []string{
						"pkg",
						"pkg/nestedpkg",
						"pkg/nestedpkg/otherpkg",
					},
					files: []string{
						"COPYING",
						"pkg/main.go",
						"pkg/nestedpkg/PATENT.md",
						"pkg/nestedpkg/otherpkg/main.go",
					},
				},
			},
			false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			h.TempDir(pr)
			baseDir := h.Path(pr)
			tc.fs.before.root = baseDir
			tc.fs.after.root = baseDir
			tc.fs.setup(t)

			fs, err := deriveFilesystemState(baseDir)
			if err != nil {
				t.Fatal(err)
			}

			_, err = pruneUnusedPackages(tc.lp, fs)
			if tc.err && err == nil {
				t.Fatalf("expected an error, got nil")
			} else if !tc.err && err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			tc.fs.assert(t)
		})
	}
}

func TestPruneNonGoFiles(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir(".")

	testcases := []struct {
		name string
		fs   fsTestCase
		err  bool
	}{
		{
			"one-file",
			fsTestCase{
				before: filesystemState{
					files: []string{
						"README.md",
					},
				},
				after: filesystemState{},
			},
			false,
		},
		{
			"multiple-files",
			fsTestCase{
				before: filesystemState{
					files: []string{
						"main.go",
						"main_test.go",
						"README",
					},
				},
				after: filesystemState{
					files: []string{
						"main.go",
						"main_test.go",
					},
				},
			},
			false,
		},
		{
			"mixed-files",
			fsTestCase{
				before: filesystemState{
					dirs: []string{
						"dir",
					},
					files: []string{
						"dir/main.go",
						"dir/main_test.go",
						"dir/db.sqlite",
					},
				},
				after: filesystemState{
					dirs: []string{
						"dir",
					},
					files: []string{
						"dir/main.go",
						"dir/main_test.go",
					},
				},
			},
			false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			h.TempDir(tc.name)
			baseDir := h.Path(tc.name)
			tc.fs.before.root = baseDir
			tc.fs.after.root = baseDir

			tc.fs.setup(t)

			fs, err := deriveFilesystemState(baseDir)
			if err != nil {
				t.Fatal(err)
			}

			err = pruneNonGoFiles(fs)
			if tc.err && err == nil {
				t.Errorf("expected an error, got nil")
			} else if !tc.err && err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			tc.fs.assert(t)
		})
	}
}

func TestPruneGoTestFiles(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir(".")

	testcases := []struct {
		name string
		fs   fsTestCase
		err  bool
	}{
		{
			"one-test-file",
			fsTestCase{
				before: filesystemState{
					files: []string{
						"main_test.go",
					},
				},
				after: filesystemState{},
			},
			false,
		},
		{
			"multiple-files",
			fsTestCase{
				before: filesystemState{
					dirs: []string{
						"dir",
					},
					files: []string{
						"dir/main_test.go",
						"dir/main2_test.go",
					},
				},
				after: filesystemState{
					dirs: []string{
						"dir",
					},
				},
			},
			false,
		},
		{
			"mixed-files",
			fsTestCase{
				before: filesystemState{
					dirs: []string{
						"dir",
					},
					files: []string{
						"dir/main.go",
						"dir/main2.go",
						"dir/main_test.go",
						"dir/main2_test.go",
					},
				},
				after: filesystemState{
					dirs: []string{
						"dir",
					},
					files: []string{
						"dir/main.go",
						"dir/main2.go",
					},
				},
			},
			false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			h.TempDir(tc.name)
			baseDir := h.Path(tc.name)
			tc.fs.before.root = baseDir
			tc.fs.after.root = baseDir

			tc.fs.setup(t)

			fs, err := deriveFilesystemState(baseDir)
			if err != nil {
				t.Fatal(err)
			}

			err = pruneGoTestFiles(fs)
			if tc.err && err == nil {
				t.Fatalf("expected an error, got nil")
			} else if !tc.err && err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			tc.fs.assert(t)
		})
	}
}

func TestPruneVendorDirs(t *testing.T) {
	tests := []struct {
		name string
		test fsTestCase
	}{
		{
			name: "vendor directory",
			test: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"package",
						"package/vendor",
					},
				},
				after: filesystemState{
					dirs: []string{
						"package",
					},
				},
			},
		},
		{
			name: "vendor file",
			test: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"package",
					},
					files: []string{
						"package/vendor",
					},
				},
				after: filesystemState{
					dirs: []string{
						"package",
					},
					files: []string{
						"package/vendor",
					},
				},
			},
		},
		{
			name: "vendor symlink",
			test: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"package",
						"package/_vendor",
					},
					links: []fsLink{
						{
							path: "package/vendor",
							to:   "_vendor",
						},
					},
				},
				after: filesystemState{
					dirs: []string{
						"package",
						"package/_vendor",
					},
				},
			},
		},
		{
			name: "nonvendor symlink",
			test: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"package",
						"package/_vendor",
					},
					links: []fsLink{
						{
							path: "package/link",
							to:   "_vendor",
						},
					},
				},
				after: filesystemState{
					dirs: []string{
						"package",
						"package/_vendor",
					},
					links: []fsLink{
						{
							path: "package/link",
							to:   "_vendor",
						},
					},
				},
			},
		},
		{
			name: "vendor symlink to file",
			test: fsTestCase{
				before: filesystemState{
					files: []string{
						"file",
					},
					links: []fsLink{
						{
							path: "vendor",
							to:   "file",
						},
					},
				},
				after: filesystemState{
					files: []string{
						"file",
					},
				},
			},
		},
		{
			name: "broken vendor symlink",
			test: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"package",
					},
					links: []fsLink{
						{
							path: "package/vendor",
							to:   "nonexistence",
						},
					},
				},
				after: filesystemState{
					dirs: []string{
						"package",
					},
					links: []fsLink{},
				},
			},
		},
		{
			name: "chained symlinks",
			test: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"_vendor",
					},
					links: []fsLink{
						{
							path: "vendor",
							to:   "vendor2",
						},
						{
							path: "vendor2",
							to:   "_vendor",
						},
					},
				},
				after: filesystemState{
					dirs: []string{
						"_vendor",
					},
					links: []fsLink{
						{
							path: "vendor2",
							to:   "_vendor",
						},
					},
				},
			},
		},
		{
			name: "circular symlinks",
			test: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"package",
					},
					links: []fsLink{
						{
							path: "package/link1",
							to:   "link2",
						},
						{
							path: "package/link2",
							to:   "link1",
						},
					},
				},
				after: filesystemState{
					dirs: []string{
						"package",
					},
					links: []fsLink{
						{
							path: "package/link1",
							to:   "link2",
						},
						{
							path: "package/link2",
							to:   "link1",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, pruneVendorDirsTestCase(test.test))
	}
}

func pruneVendorDirsTestCase(tc fsTestCase) func(*testing.T) {
	return func(t *testing.T) {
		tempDir, err := ioutil.TempDir("", "pruneVendorDirsTestCase")
		if err != nil {
			t.Fatalf("ioutil.TempDir err=%q", err)
		}
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Errorf("os.RemoveAll(%q) err=%q", tempDir, err)
			}
		}()

		tc.before.root = tempDir
		tc.after.root = tempDir

		tc.setup(t)

		fs, err := deriveFilesystemState(tempDir)
		if err != nil {
			t.Fatalf("deriveFilesystemState failed: %s", err)
		}

		if err := pruneVendorDirs(fs); err != nil {
			t.Errorf("pruneVendorDirs err=%q", err)
		}

		tc.assert(t)
	}
}

func TestDeleteEmptyDirs(t *testing.T) {
	testcases := []struct {
		name string
		fs   fsTestCase
	}{
		{
			name: "empty-dir",
			fs: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"pkg1",
					},
				},
				after: filesystemState{},
			},
		},
		{
			name: "nested-empty-dirs",
			fs: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"pkg1",
						"pkg1/pkg2",
					},
				},
				after: filesystemState{},
			},
		},
		{
			name: "non-empty-dir",
			fs: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"pkg1",
					},
					files: []string{
						"pkg1/file1",
					},
				},
				after: filesystemState{
					dirs: []string{
						"pkg1",
					},
					files: []string{
						"pkg1/file1",
					},
				},
			},
		},
		{
			name: "mixed-dirs",
			fs: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"pkg1",
						"pkg1/pkg2",
					},
					files: []string{
						"pkg1/file1",
					},
				},
				after: filesystemState{
					dirs: []string{
						"pkg1",
					},
					files: []string{
						"pkg1/file1",
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			h := test.NewHelper(t)
			h.Cleanup()
			h.TempDir(".")

			tc.fs.before.root = h.Path(".")
			tc.fs.after.root = h.Path(".")

			if err := tc.fs.before.setup(); err != nil {
				t.Fatal("unexpected error in fs setup: ", err)
			}

			if err := deleteEmptyDirs(tc.fs.before); err != nil {
				t.Fatal("unexpected error in deleteEmptyDirs: ", err)
			}

			tc.fs.assert(t)
		})
	}
}
