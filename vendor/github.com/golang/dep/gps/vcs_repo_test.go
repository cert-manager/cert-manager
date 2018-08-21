// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/Masterminds/vcs"
)

// original implementation of these test files come from
// https://github.com/Masterminds/vcs test files

const gitRemoteTestRepo = "https://github.com/Masterminds/VCSTestRepo"

func TestErrs(t *testing.T) {
	err := newVcsLocalErrorOr(context.Canceled, nil, "", "")
	if err != context.Canceled {
		t.Errorf("context errors should always pass through, got %s", err)
	}
	err = newVcsRemoteErrorOr(context.Canceled, nil, "", "")
	if err != context.Canceled {
		t.Errorf("context errors should always pass through, got %s", err)
	}
	err = newVcsLocalErrorOr(context.DeadlineExceeded, nil, "", "")
	if err != context.DeadlineExceeded {
		t.Errorf("context errors should always pass through, got %s", err)
	}
	err = newVcsRemoteErrorOr(context.DeadlineExceeded, nil, "", "")
	if err != context.DeadlineExceeded {
		t.Errorf("context errors should always pass through, got %s", err)
	}

	err = newVcsLocalErrorOr(errors.New("bar"), nil, "foo", "baz")
	if _, is := err.(*vcs.LocalError); !is {
		t.Errorf("should have gotten local error, got %T %v", err, err)
	}
	err = newVcsRemoteErrorOr(errors.New("bar"), nil, "foo", "baz")
	if _, is := err.(*vcs.RemoteError); !is {
		t.Errorf("should have gotten remote error, got %T %v", err, err)
	}
}

func testSvnRepo(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	ctx := context.Background()
	tempDir, err := ioutil.TempDir("", "go-vcs-svn-tests")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	rep, err := vcs.NewSvnRepo("https://github.com/Masterminds/VCSTestRepo/trunk", tempDir+string(os.PathSeparator)+"VCSTestRepo")
	if err != nil {
		t.Fatal(err)
	}
	repo := &svnRepo{rep}

	// Do an initial checkout.
	err = repo.get(ctx)
	if err != nil {
		t.Fatalf("Unable to checkout SVN repo. Err was %s", err)
	}

	// Verify SVN repo is a SVN repo
	if !repo.CheckLocal() {
		t.Fatal("Problem checking out repo or SVN CheckLocal is not working")
	}

	// Update the version to a previous version.
	err = repo.updateVersion(ctx, "r2")
	if err != nil {
		t.Fatalf("Unable to update SVN repo version. Err was %s", err)
	}

	// Use Version to verify we are on the right version.
	v, err := repo.Version()
	if err != nil {
		t.Fatal(err)
	}
	if v != "2" {
		t.Fatal("Error checking checked SVN out version")
	}

	// Perform an update which should take up back to the latest version.
	err = repo.fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Make sure we are on a newer version because of the update.
	v, err = repo.Version()
	if err != nil {
		t.Fatal(err)
	}
	if v == "2" {
		t.Fatal("Error with version. Still on old version. Update failed")
	}

	ci, err := repo.CommitInfo("2")
	if err != nil {
		t.Fatal(err)
	}
	if ci.Commit != "2" {
		t.Error("Svn.CommitInfo wrong commit id")
	}
	if ci.Author != "matt.farina" {
		t.Error("Svn.CommitInfo wrong author")
	}
	if ci.Message != "Update README.md" {
		t.Error("Svn.CommitInfo wrong message")
	}
	ti, err := time.Parse(time.RFC3339Nano, "2015-07-29T13:46:20.000000Z")
	if err != nil {
		t.Fatal(err)
	}
	if !ti.Equal(ci.Date) {
		t.Error("Svn.CommitInfo wrong date")
	}

	_, err = repo.CommitInfo("555555555")
	if err != vcs.ErrRevisionUnavailable {
		t.Error("Svn didn't return expected ErrRevisionUnavailable")
	}
}

func testHgRepo(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	ctx := context.Background()
	tempDir, err := ioutil.TempDir("", "go-vcs-hg-tests")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	rep, err := vcs.NewHgRepo("https://bitbucket.org/mattfarina/testhgrepo", tempDir+"/testhgrepo")
	if err != nil {
		t.Fatal(err)
	}

	repo := &hgRepo{rep}

	// Do an initial clone.
	err = repo.get(ctx)
	if err != nil {
		t.Fatalf("Unable to clone Hg repo. Err was %s", err)
	}

	// Verify Hg repo is a Hg repo
	if !repo.CheckLocal() {
		t.Fatal("Problem checking out repo or Hg CheckLocal is not working")
	}

	// Set the version using the short hash.
	err = repo.updateVersion(ctx, "a5494ba2177f")
	if err != nil {
		t.Fatalf("Unable to update Hg repo version. Err was %s", err)
	}

	// Use Version to verify we are on the right version.
	v, err := repo.Version()
	if err != nil {
		t.Fatal(err)
	}
	if v != "a5494ba2177ff9ef26feb3c155dfecc350b1a8ef" {
		t.Fatalf("Error checking checked out Hg version: %s", v)
	}

	// Perform an update.
	err = repo.fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
}

func testGitRepo(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	ctx := context.Background()
	tempDir, err := ioutil.TempDir("", "go-vcs-git-tests")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	rep, err := vcs.NewGitRepo(gitRemoteTestRepo, tempDir+"/VCSTestRepo")
	if err != nil {
		t.Fatal(err)
	}

	repo := &gitRepo{rep}

	// Do an initial clone.
	err = repo.get(ctx)
	if err != nil {
		t.Fatalf("Unable to clone Git repo. Err was %s", err)
	}

	// Verify Git repo is a Git repo
	if !repo.CheckLocal() {
		t.Fatal("Problem checking out repo or Git CheckLocal is not working")
	}

	// Perform an update.
	err = repo.fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}

	v, err := repo.Current()
	if err != nil {
		t.Fatalf("Error trying Git Current: %s", err)
	}
	if v != "master" {
		t.Fatalf("Current failed to detect Git on tip of master. Got version: %s", v)
	}

	// Set the version using the short hash.
	err = repo.updateVersion(ctx, "806b07b")
	if err != nil {
		t.Fatalf("Unable to update Git repo version. Err was %s", err)
	}

	// Once a ref has been checked out the repo is in a detached head state.
	// Trying to pull in an update in this state will cause an error. Update
	// should cleanly handle this. Pulling on a branch (tested elsewhere) and
	// skipping that here.
	err = repo.fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Use Version to verify we are on the right version.
	v, err = repo.Version()
	if err != nil {
		t.Fatal(err)
	}
	if v != "806b07b08faa21cfbdae93027904f80174679402" {
		t.Fatal("Error checking checked out Git version")
	}
}

func testBzrRepo(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	ctx := context.Background()
	tempDir, err := ioutil.TempDir("", "go-vcs-bzr-tests")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	rep, err := vcs.NewBzrRepo("https://launchpad.net/govcstestbzrrepo", tempDir+"/govcstestbzrrepo")
	if err != nil {
		t.Fatal(err)
	}

	repo := &bzrRepo{rep}

	// Do an initial clone.
	err = repo.get(ctx)
	if err != nil {
		t.Fatalf("Unable to clone Bzr repo. Err was %s", err)
	}

	// Verify Bzr repo is a Bzr repo
	if !repo.CheckLocal() {
		t.Fatal("Problem checking out repo or Bzr CheckLocal is not working")
	}

	v, err := repo.Current()
	if err != nil {
		t.Fatalf("Error trying Bzr Current: %s", err)
	}
	if v != "-1" {
		t.Fatalf("Current failed to detect Bzr on tip of branch. Got version: %s", v)
	}

	err = repo.updateVersion(ctx, "2")
	if err != nil {
		t.Fatalf("Unable to update Bzr repo version. Err was %s", err)
	}

	// Use Version to verify we are on the right version.
	v, err = repo.Version()
	if err != nil {
		t.Fatal(err)
	}
	if v != "2" {
		t.Fatal("Error checking checked out Bzr version")
	}

	v, err = repo.Current()
	if err != nil {
		t.Fatalf("Error trying Bzr Current: %s", err)
	}
	if v != "2" {
		t.Fatalf("Current failed to detect Bzr on rev 2 of branch. Got version: %s", v)
	}
}
