package vcs

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"
	//"log"
	"os"
	"testing"
)

// Canary test to ensure GitRepo implements the Repo interface.
var _ Repo = &GitRepo{}

// To verify git is working we perform integration testing
// with a known git service.

func TestGit(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-vcs-git-tests")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	repo, err := NewGitRepo("https://github.com/Masterminds/VCSTestRepo", tempDir+"/VCSTestRepo")
	if err != nil {
		t.Error(err)
	}

	if repo.Vcs() != Git {
		t.Error("Git is detecting the wrong type")
	}

	// Check the basic getters.
	if repo.Remote() != "https://github.com/Masterminds/VCSTestRepo" {
		t.Error("Remote not set properly")
	}
	if repo.LocalPath() != tempDir+"/VCSTestRepo" {
		t.Error("Local disk location not set properly")
	}

	//Logger = log.New(os.Stdout, "", log.LstdFlags)

	// Do an initial clone.
	err = repo.Get()
	if err != nil {
		t.Errorf("Unable to clone Git repo. Err was %s", err)
	}

	// Verify Git repo is a Git repo
	if !repo.CheckLocal() {
		t.Error("Problem checking out repo or Git CheckLocal is not working")
	}

	// Test internal lookup mechanism used outside of Git specific functionality.
	ltype, err := DetectVcsFromFS(tempDir + "/VCSTestRepo")
	if err != nil {
		t.Error("detectVcsFromFS unable to Git repo")
	}
	if ltype != Git {
		t.Errorf("detectVcsFromFS detected %s instead of Git type", ltype)
	}

	// Test NewRepo on existing checkout. This should simply provide a working
	// instance without error based on looking at the local directory.
	nrepo, nrerr := NewRepo("https://github.com/Masterminds/VCSTestRepo", tempDir+"/VCSTestRepo")
	if nrerr != nil {
		t.Error(nrerr)
	}
	// Verify the right oject is returned. It will check the local repo type.
	if !nrepo.CheckLocal() {
		t.Error("Wrong version returned from NewRepo")
	}

	// Perform an update.
	err = repo.Update()
	if err != nil {
		t.Error(err)
	}

	v, err := repo.Current()
	if err != nil {
		t.Errorf("Error trying Git Current: %s", err)
	}
	if v != "master" {
		t.Errorf("Current failed to detect Git on tip of master. Got version: %s", v)
	}

	// Set the version using the short hash.
	err = repo.UpdateVersion("806b07b")
	if err != nil {
		t.Errorf("Unable to update Git repo version. Err was %s", err)
	}

	// Once a ref has been checked out the repo is in a detached head state.
	// Trying to pull in an update in this state will cause an error. Update
	// should cleanly handle this. Pulling on a branch (tested elsewhere) and
	// skipping that here.
	err = repo.Update()
	if err != nil {
		t.Error(err)
	}

	// Use Version to verify we are on the right version.
	v, err = repo.Version()
	if v != "806b07b08faa21cfbdae93027904f80174679402" {
		t.Error("Error checking checked out Git version")
	}
	if err != nil {
		t.Error(err)
	}

	v, err = repo.Current()
	if err != nil {
		t.Errorf("Error trying Git Current for ref: %s", err)
	}
	if v != "806b07b08faa21cfbdae93027904f80174679402" {
		t.Errorf("Current failed to detect Git on ref of branch. Got version: %s", v)
	}

	// Use Date to verify we are on the right commit.
	d, err := repo.Date()
	if d.Format(longForm) != "2015-07-29 09:46:39 -0400" {
		t.Error("Error checking checked out Git commit date")
	}
	if err != nil {
		t.Error(err)
	}

	// Verify that we can set the version something other than short hash
	err = repo.UpdateVersion("master")
	if err != nil {
		t.Errorf("Unable to update Git repo version. Err was %s", err)
	}
	err = repo.UpdateVersion("806b07b08faa21cfbdae93027904f80174679402")
	if err != nil {
		t.Errorf("Unable to update Git repo version. Err was %s", err)
	}
	v, err = repo.Version()
	if v != "806b07b08faa21cfbdae93027904f80174679402" {
		t.Error("Error checking checked out Git version")
	}
	if err != nil {
		t.Error(err)
	}

	tags, err := repo.Tags()
	if err != nil {
		t.Error(err)
	}

	var hasRelTag bool
	var hasOffMasterTag bool

	for _, tv := range tags {
		if tv == "1.0.0" {
			hasRelTag = true
		} else if tv == "off-master-tag" {
			hasOffMasterTag = true
		}
	}

	if !hasRelTag {
		t.Error("Git tags unable to find release tag on master")
	}
	if !hasOffMasterTag {
		t.Error("Git tags did not fetch tags not on master")
	}

	tags, err = repo.TagsFromCommit("74dd547545b7df4aa285bcec1b54e2b76f726395")
	if err != nil {
		t.Error(err)
	}
	if len(tags) != 0 {
		t.Error("Git is incorrectly returning tags for a commit")
	}

	tags, err = repo.TagsFromCommit("30605f6ac35fcb075ad0bfa9296f90a7d891523e")
	if err != nil {
		t.Error(err)
	}
	if len(tags) != 1 || tags[0] != "1.0.0" {
		t.Error("Git is incorrectly returning tags for a commit")
	}

	branches, err := repo.Branches()
	if err != nil {
		t.Error(err)
	}
	// The branches should be HEAD, master, other, and test.
	if branches[3] != "test" {
		t.Error("Git is incorrectly returning branches")
	}

	if !repo.IsReference("1.0.0") {
		t.Error("Git is reporting a reference is not one")
	}

	if repo.IsReference("foo") {
		t.Error("Git is reporting a non-existent reference is one")
	}

	if repo.IsDirty() {
		t.Error("Git incorrectly reporting dirty")
	}

	ci, err := repo.CommitInfo("806b07b08faa21cfbdae93027904f80174679402")
	if err != nil {
		t.Error(err)
	}
	if ci.Commit != "806b07b08faa21cfbdae93027904f80174679402" {
		t.Error("Git.CommitInfo wrong commit id")
	}
	if ci.Author != "Matt Farina <matt@mattfarina.com>" {
		t.Error("Git.CommitInfo wrong author")
	}
	if ci.Message != "Update README.md" {
		t.Error("Git.CommitInfo wrong message")
	}
	ti, err := time.Parse(time.RFC1123Z, "Wed, 29 Jul 2015 09:46:39 -0400")
	if err != nil {
		t.Error(err)
	}
	if !ti.Equal(ci.Date) {
		t.Error("Git.CommitInfo wrong date")
	}

	_, err = repo.CommitInfo("asdfasdfasdf")
	if err != ErrRevisionUnavailable {
		t.Error("Git didn't return expected ErrRevisionUnavailable")
	}

	tempDir2, err := ioutil.TempDir("", "go-vcs-git-tests-export")
	if err != nil {
		t.Fatalf("Error creating temp directory: %s", err)
	}
	defer func() {
		err = os.RemoveAll(tempDir2)
		if err != nil {
			t.Error(err)
		}
	}()

	exportDir := filepath.Join(tempDir2, "src")

	err = repo.ExportDir(exportDir)
	if err != nil {
		t.Errorf("Unable to export Git repo. Err was %s", err)
	}

	_, err = os.Stat(filepath.Join(exportDir, "README.md"))
	if err != nil {
		t.Errorf("Error checking exported file in Git: %s", err)
	}

	_, err = os.Stat(filepath.Join(exportDir, string(repo.Vcs())))
	if err != nil {
		if found := os.IsNotExist(err); !found {
			t.Errorf("Error checking exported metadata in Git: %s", err)
		}
	} else {
		t.Error("Error checking Git metadata. It exists.")
	}
}

func TestGitCheckLocal(t *testing.T) {
	// Verify repo.CheckLocal fails for non-Git directories.
	// TestGit is already checking on a valid repo
	tempDir, err := ioutil.TempDir("", "go-vcs-git-tests")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	repo, _ := NewGitRepo("", tempDir)
	if repo.CheckLocal() {
		t.Error("Git CheckLocal does not identify non-Git location")
	}

	// Test NewRepo when there's no local. This should simply provide a working
	// instance without error based on looking at the remote localtion.
	_, nrerr := NewRepo("https://github.com/Masterminds/VCSTestRepo", tempDir+"/VCSTestRepo")
	if nrerr != nil {
		t.Error(nrerr)
	}
}

func TestGitPing(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-vcs-git-tests")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	repo, err := NewGitRepo("https://github.com/Masterminds/VCSTestRepo", tempDir)
	if err != nil {
		t.Error(err)
	}

	ping := repo.Ping()
	if !ping {
		t.Error("Git unable to ping working repo")
	}

	repo, err = NewGitRepo("https://github.com/Masterminds/ihopethisneverexistsbecauseitshouldnt", tempDir)
	if err != nil {
		t.Error(err)
	}

	ping = repo.Ping()
	if ping {
		t.Error("Git got a ping response from when it should not have")
	}
}

func TestGitInit(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-vcs-git-tests")
	repoDir := tempDir + "/repo"
	if err != nil {
		t.Error(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	repo, err := NewGitRepo(repoDir, repoDir)
	if err != nil {
		t.Error(err)
	}

	err = repo.Init()
	if err != nil {
		t.Error(err)
	}

	_, err = repo.RunFromDir("git", "status")
	if err != nil {
		t.Error(err)
	}
}

func TestGitSubmoduleHandling(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-vcs-git-submodule-tests")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	dumplocal := func(err error) string {
		if terr, ok := err.(*LocalError); ok {
			return fmt.Sprintf("msg: %s\norig: %s\nout: %s", terr.Error(), terr.Original(), terr.Out())
		}
		return err.Error()
	}

	subdirExists := func(dir ...string) bool {
		_, err := os.Stat(filepath.Join(append([]string{tempDir}, dir...)...))
		return err == nil
	}

	// Initial clone should get version with two submodules, each of which have
	// their own submodule
	repo, err := NewGitRepo("https://github.com/sdboyer/subm", tempDir)
	if err != nil {
		t.Fatal(dumplocal(err))
	}
	err = repo.Get()
	if err != nil {
		t.Fatalf("unable to clone Git repo. Err was %s", dumplocal(err))
	}

	// Verify we are on the right version.
	v, err := repo.Version()
	if v != "18e3a5f6fc7f6d577e732e7a5ab2caf990efbf8f" {
		t.Fatalf("did not start from expected rev, tests could fail - bailing out (got %s)", v)
	}
	if err != nil {
		t.Fatal(dumplocal(err))
	}

	if !subdirExists("subm1", ".git") {
		t.Fatal("subm1 submodule does not exist on initial clone/checkout")
	}
	if !subdirExists("subm1", "dep-test", ".git") {
		t.Fatal("dep-test submodule nested under subm1 does not exist on initial clone/checkout")
	}

	if !subdirExists("subm-again", ".git") {
		t.Fatal("subm-again submodule does not exist on initial clone/checkout")
	}
	if !subdirExists("subm-again", "dep-test", ".git") {
		t.Fatal("dep-test submodule nested under subm-again does not exist on initial clone/checkout")
	}

	// Now switch to version with no submodules, make sure they all go away
	err = repo.UpdateVersion("e677f82015f72ac1c8fafa66b5463163b3597af2")
	if err != nil {
		t.Fatalf("checking out needed version failed with err: %s", dumplocal(err))
	}

	if subdirExists("subm1") {
		t.Fatal("checking out version without submodule did not clean up immediate submodules")
	}
	if subdirExists("subm1", "dep-test") {
		t.Fatal("checking out version without submodule did not clean up nested submodules")
	}
	if subdirExists("subm-again") {
		t.Fatal("checking out version without submodule did not clean up immediate submodules")
	}
	if subdirExists("subm-again", "dep-test") {
		t.Fatal("checking out version without submodule did not clean up nested submodules")
	}

	err = repo.UpdateVersion("aaf7aa1bc4c3c682cc530eca8f80417088ee8540")
	if err != nil {
		t.Fatalf("checking out needed version failed with err: %s", dumplocal(err))
	}

	if !subdirExists("subm1", ".git") {
		t.Fatal("checking out version with immediate submodule did not set up git subrepo")
	}

	err = repo.UpdateVersion("6cc4669af468f3b4f16e7e96275ad01ade5b522f")
	if err != nil {
		t.Fatalf("checking out needed version failed with err: %s", dumplocal(err))
	}

	if !subdirExists("subm1", "dep-test", ".git") {
		t.Fatal("checking out version with nested submodule did not set up nested git subrepo")
	}

	err = repo.UpdateVersion("aaf7aa1bc4c3c682cc530eca8f80417088ee8540")
	if err != nil {
		t.Fatalf("checking out needed version failed with err: %s", dumplocal(err))
	}

	if subdirExists("subm1", "dep-test") {
		t.Fatal("rolling back to version without nested submodule did not clean up the nested submodule")
	}

	err = repo.UpdateVersion("18e3a5f6fc7f6d577e732e7a5ab2caf990efbf8f")
	if err != nil {
		t.Fatalf("checking out needed version failed with err: %s", dumplocal(err))
	}

	if !subdirExists("subm1", ".git") {
		t.Fatal("subm1 submodule does not exist after switch from other commit")
	}
	if !subdirExists("subm1", "dep-test", ".git") {
		t.Fatal("dep-test submodule nested under subm1 does not exist after switch from other commit")
	}

	if !subdirExists("subm-again", ".git") {
		t.Fatal("subm-again submodule does not exist after switch from other commit")
	}
	if !subdirExists("subm-again", "dep-test", ".git") {
		t.Fatal("dep-test submodule nested under subm-again does not exist after switch from other commit")
	}

}

func TestGitSubmoduleHandling2(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-vcs-git-submodule-tests2")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	repo, err := NewGitRepo("https://github.com/cloudfoundry/sonde-go", tempDir+"/VCSTestRepo2")
	if err != nil {
		t.Error(err)
	}

	if repo.Vcs() != Git {
		t.Error("Git is detecting the wrong type")
	}

	// Check the basic getters.
	if repo.Remote() != "https://github.com/cloudfoundry/sonde-go" {
		t.Error("Remote not set properly")
	}
	if repo.LocalPath() != tempDir+"/VCSTestRepo2" {
		t.Error("Local disk location not set properly")
	}

	//Logger = log.New(os.Stdout, "", log.LstdFlags)

	// Do an initial clone.
	err = repo.Get()
	if err != nil {
		t.Errorf("Unable to clone Git repo. Err was %s", err)
	}

	// Verify Git repo is a Git repo
	if !repo.CheckLocal() {
		t.Error("Problem checking out repo or Git CheckLocal is not working")
	}

	// Test internal lookup mechanism used outside of Git specific functionality.
	ltype, err := DetectVcsFromFS(tempDir + "/VCSTestRepo2")
	if err != nil {
		t.Error("detectVcsFromFS unable to Git repo")
	}
	if ltype != Git {
		t.Errorf("detectVcsFromFS detected %s instead of Git type", ltype)
	}

	// Test NewRepo on existing checkout. This should simply provide a working
	// instance without error based on looking at the local directory.
	nrepo, nrerr := NewRepo("https://github.com/cloudfoundry/sonde-go", tempDir+"/VCSTestRepo2")
	if nrerr != nil {
		t.Error(nrerr)
	}
	// Verify the right oject is returned. It will check the local repo type.
	if !nrepo.CheckLocal() {
		t.Error("Wrong version returned from NewRepo")
	}

	// Perform an update.
	err = repo.Update()
	if err != nil {
		t.Error(err)
	}

	v, err := repo.Current()
	if err != nil {
		t.Errorf("Error trying Git Current: %s", err)
	}
	if v != "master" {
		t.Errorf("Current failed to detect Git on tip of master. Got version: %s", v)
	}


	tempDir2, err := ioutil.TempDir("", "go-vcs-git-tests-export")
	if err != nil {
		t.Fatalf("Error creating temp directory: %s", err)
	}
	defer func() {
		err = os.RemoveAll(tempDir2)
		if err != nil {
			t.Error(err)
		}
	}()

	exportDir := filepath.Join(tempDir2, "src")

	err = repo.ExportDir(exportDir)
	if err != nil {
		t.Errorf("Unable to export Git repo. Err was %s", err)
	}

	_, err = os.Stat(filepath.Join(exportDir, "README.md"))
	if err != nil {
		t.Errorf("Error checking exported file in Git: %s", err)
	}

	_, err = os.Stat(filepath.Join( filepath.Join(exportDir, "definitions"), "README.md"))
	if err != nil {
		t.Errorf("Error checking exported file in Git: %s", err)
	}

	_, err = os.Stat(filepath.Join(exportDir, string(repo.Vcs())))
	if err != nil {
		if found := os.IsNotExist(err); !found {
			t.Errorf("Error checking exported metadata in Git: %s", err)
		}
	} else {
		t.Error("Error checking Git metadata. It exists.")
	}
}
