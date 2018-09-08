// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/golang/dep/internal/test"
)

// This file contains utilities for running tests around file system state.

type fsTestCase struct {
	before, after filesystemState
}

// assert makes sure that the tc.after state matches the state of the actual host
// file system at tc.after.root.
func (tc fsTestCase) assert(t *testing.T) {
	dirMap := make(map[string]bool)
	fileMap := make(map[string]bool)
	linkMap := make(map[string]bool)

	for _, d := range tc.after.dirs {
		dirMap[filepath.Join(tc.after.root, d)] = true
	}
	for _, f := range tc.after.files {
		fileMap[filepath.Join(tc.after.root, f)] = true
	}
	for _, l := range tc.after.links {
		linkMap[filepath.Join(tc.after.root, l.path)] = true
	}

	err := filepath.Walk(tc.after.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Errorf("filepath.Walk path=%q  err=%q", path, err)
			return err
		}

		if path == tc.after.root {
			return nil
		}

		// Careful! Have to check whether the path is a symlink first because, on
		// windows, a symlink to a directory will return 'true' for info.IsDir().
		if (info.Mode() & os.ModeSymlink) != 0 {
			if linkMap[path] {
				delete(linkMap, path)
			} else {
				t.Errorf("unexpected symlink exists %q", path)
			}
			return nil
		}

		if info.IsDir() {
			if dirMap[path] {
				delete(dirMap, path)
			} else {
				t.Errorf("unexpected directory exists %q", path)
			}
			return nil
		}

		if fileMap[path] {
			delete(fileMap, path)
		} else {
			t.Errorf("unexpected file exists %q", path)
		}
		return nil
	})

	if err != nil {
		t.Errorf("filesystem.Walk err=%q", err)
	}

	for d := range dirMap {
		t.Errorf("could not find expected directory %q", d)
	}
	for f := range fileMap {
		t.Errorf("could not find expected file %q", f)
	}
	for l := range linkMap {
		t.Errorf("could not find expected symlink %q", l)
	}
}

// setup inflates fs onto the actual host file system at tc.before.root.
// It doesn't delete existing files and should be used on empty roots only.
func (tc fsTestCase) setup(t *testing.T) {
	if err := tc.before.setup(); err != nil {
		t.Fatal(err)
	}
}

func TestDeriveFilesystemState(t *testing.T) {
	testcases := []struct {
		name string
		fs   fsTestCase
	}{
		{
			name: "simple-case",
			fs: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"simple-dir",
					},
					files: []string{
						"simple-file",
					},
				},
				after: filesystemState{
					dirs: []string{
						"simple-dir",
					},
					files: []string{
						"simple-file",
					},
				},
			},
		},
		{
			name: "simple-symlink-case",
			fs: fsTestCase{
				before: filesystemState{
					dirs: []string{
						"simple-dir",
					},
					files: []string{
						"simple-file",
					},
					links: []fsLink{
						{
							path:   "link",
							to:     "nonexisting",
							broken: true,
						},
					},
				},
				after: filesystemState{
					dirs: []string{
						"simple-dir",
					},
					files: []string{
						"simple-file",
					},
					links: []fsLink{
						{
							path:   "link",
							to:     "",
							broken: true,
						},
					},
				},
			},
		},
		{
			name: "complex-symlink-case",
			fs: fsTestCase{
				before: filesystemState{
					links: []fsLink{
						{
							path:     "link1",
							to:       "link2",
							circular: true,
						},
						{
							path:     "link2",
							to:       "link1",
							circular: true,
						},
					},
				},
				after: filesystemState{
					links: []fsLink{
						{
							path:     "link1",
							to:       "",
							circular: true,
						},
						{
							path:     "link2",
							to:       "",
							circular: true,
						},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		h := test.NewHelper(t)

		h.TempDir(tc.name)

		tc.fs.before.root = h.Path(tc.name)
		tc.fs.after.root = h.Path(tc.name)

		tc.fs.setup(t)

		state, err := deriveFilesystemState(h.Path(tc.name))
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(tc.fs.after, state) {
			fmt.Println(tc.fs.after)
			fmt.Println(state)
			t.Fatal("filesystem state mismatch")
		}

		h.Cleanup()
	}
}
