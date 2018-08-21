// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/Masterminds/vcs"
)

func TestMaybeGitSource_try(t *testing.T) {
	t.Parallel()

	tempDir, err := ioutil.TempDir("", "go-try-happy-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	url, err := url.Parse(gitRemoteTestRepo)
	if err != nil {
		t.Fatal(err)
	}
	var ms maybeSource = maybeGitSource{url: url}
	_, err = ms.try(context.Background(), tempDir)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMaybeGitSource_try_recovery(t *testing.T) {
	t.Parallel()

	tempDir, err := ioutil.TempDir("", "go-try-recovery-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(cwd, "_testdata", "badrepo", "corrupt_dot_git_directory.tar")
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	dest := filepath.Join(tempDir, ".git")
	err = untar(dest, f)
	if err != nil {
		t.Fatalf("could not untar corrupt repo into temp folder: %v\n", err)
	}

	_, err = vcs.NewGitRepo(gitRemoteTestRepo, tempDir)
	if err != nil {
		if _, ok := err.(*vcs.LocalError); !ok {
			t.Fatalf("expected a local error but got: %v\n", err)
		}
	} else {
		t.Fatal("expected getVCSRepo to fail when pointing to a corrupt local path. It is possible that vcs.GitNewRepo updated to gracefully handle this test scenario. Check the return of vcs.GitNewRepo.")
	}

	url, err := url.Parse(gitRemoteTestRepo)
	if err != nil {
		t.Fatal(err)
	}
	var ms maybeSource = maybeGitSource{url: url}
	_, err = ms.try(context.Background(), tempDir)
	if err != nil {
		t.Fatal(err)
	}
}

func untar(dst string, r io.Reader) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()

		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case header == nil:
			continue
		}

		target := filepath.Join(dst, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			defer f.Close()

			if _, err := io.Copy(f, tr); err != nil {
				return err
			}
		}
	}
}
