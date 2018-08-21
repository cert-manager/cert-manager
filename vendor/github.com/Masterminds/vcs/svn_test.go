package vcs

import (
	"io/ioutil"
	"path/filepath"
	"time"
	//"log"
	"os"
	"testing"
)

// To verify svn is working we perform integration testing
// with a known svn service.

// Canary test to ensure SvnRepo implements the Repo interface.
var _ Repo = &SvnRepo{}

func TestSvn(t *testing.T) {

	tempDir, err := ioutil.TempDir("", "go-vcs-svn-tests")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	repo, err := NewSvnRepo("https://github.com/Masterminds/VCSTestRepo/trunk", tempDir+string(os.PathSeparator)+"VCSTestRepo")
	if err != nil {
		t.Error(err)
	}

	if repo.Vcs() != Svn {
		t.Error("Svn is detecting the wrong type")
	}

	// Check the basic getters.
	if repo.Remote() != "https://github.com/Masterminds/VCSTestRepo/trunk" {
		t.Error("Remote not set properly")
	}
	if repo.LocalPath() != tempDir+string(os.PathSeparator)+"VCSTestRepo" {
		t.Error("Local disk location not set properly")
	}

	//Logger = log.New(os.Stdout, "", log.LstdFlags)

	// Do an initial checkout.
	err = repo.Get()
	if err != nil {
		t.Errorf("Unable to checkout SVN repo. Err was %s", err)
	}

	// Verify SVN repo is a SVN repo
	if !repo.CheckLocal() {
		t.Error("Problem checking out repo or SVN CheckLocal is not working")
	}

	// Verify an incorrect remote is caught when NewSvnRepo is used on an existing location
	_, nrerr := NewSvnRepo("https://github.com/Masterminds/VCSTestRepo/unknownbranch", tempDir+"/VCSTestRepo")
	if nrerr != ErrWrongRemote {
		t.Error("ErrWrongRemote was not triggered for SVN")
	}

	// Test internal lookup mechanism used outside of Hg specific functionality.
	ltype, err := DetectVcsFromFS(tempDir + "/VCSTestRepo")
	if err != nil {
		t.Error("detectVcsFromFS unable to Svn repo")
	}
	if ltype != Svn {
		t.Errorf("detectVcsFromFS detected %s instead of Svn type", ltype)
	}

	// Commenting out auto-detection tests for SVN. NewRepo automatically detects
	// GitHub to be a Git repo and that's an issue for this test. Need an
	// SVN host that can autodetect from before using this test again.
	//
	// Test NewRepo on existing checkout. This should simply provide a working
	// instance without error based on looking at the local directory.
	// nrepo, nrerr := NewRepo("https://github.com/Masterminds/VCSTestRepo/trunk", tempDir+"/VCSTestRepo")
	// if nrerr != nil {
	// 	t.Error(nrerr)
	// }
	// // Verify the right oject is returned. It will check the local repo type.
	// if nrepo.CheckLocal() == false {
	// 	t.Error("Wrong version returned from NewRepo")
	// }

	v, err := repo.Current()
	if err != nil {
		t.Errorf("Error trying Svn Current: %s", err)
	}
	if v != "HEAD" {
		t.Errorf("Current failed to detect Svn on HEAD. Got version: %s", v)
	}

	// Update the version to a previous version.
	err = repo.UpdateVersion("r2")
	if err != nil {
		t.Errorf("Unable to update SVN repo version. Err was %s", err)
	}

	// Use Version to verify we are on the right version.
	v, err = repo.Version()
	if v != "2" {
		t.Error("Error checking checked SVN out version")
	}
	if err != nil {
		t.Error(err)
	}

	v, err = repo.Current()
	if err != nil {
		t.Errorf("Error trying Svn Current for ref: %s", err)
	}
	if v != "2" {
		t.Errorf("Current failed to detect Svn on HEAD. Got version: %s", v)
	}

	// Perform an update which should take up back to the latest version.
	err = repo.Update()
	if err != nil {
		t.Error(err)
	}

	// Make sure we are on a newer version because of the update.
	v, err = repo.Version()
	if v == "2" {
		t.Error("Error with version. Still on old version. Update failed")
	}
	if err != nil {
		t.Error(err)
	}

	// Use Date to verify we are on the right commit.
	d, err := repo.Date()
	if d.Format(longForm) != "2015-07-29 13:47:03 +0000" {
		t.Error("Error checking checked out Svn commit date")
	}
	if err != nil {
		t.Error(err)
	}

	tags, err := repo.Tags()
	if err != nil {
		t.Error(err)
	}
	if len(tags) != 0 {
		t.Error("Svn is incorrectly returning tags")
	}

	tags, err = repo.TagsFromCommit("2")
	if err != nil {
		t.Error(err)
	}
	if len(tags) != 0 {
		t.Error("Svn is incorrectly returning tags for a commit")
	}

	branches, err := repo.Branches()
	if err != nil {
		t.Error(err)
	}
	if len(branches) != 0 {
		t.Error("Svn is incorrectly returning branches")
	}

	if !repo.IsReference("r4") {
		t.Error("Svn is reporting a reference is not one")
	}

	if repo.IsReference("55") {
		t.Error("Svn is reporting a non-existent reference is one")
	}

	if repo.IsDirty() {
		t.Error("Svn incorrectly reporting dirty")
	}

	ci, err := repo.CommitInfo("2")
	if err != nil {
		t.Error(err)
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
		t.Error(err)
	}
	if !ti.Equal(ci.Date) {
		t.Error("Svn.CommitInfo wrong date")
	}

	_, err = repo.CommitInfo("555555555")
	if err != ErrRevisionUnavailable {
		t.Error("Svn didn't return expected ErrRevisionUnavailable")
	}

	tempDir2, err := ioutil.TempDir("", "go-vcs-svn-tests-export")
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
		t.Errorf("Unable to export Svn repo. Err was %s", err)
	}

	_, err = os.Stat(filepath.Join(exportDir, "README.md"))
	if err != nil {
		t.Errorf("Error checking exported file in Svn: %s", err)
	}

	_, err = os.Stat(filepath.Join(exportDir, string(repo.Vcs())))
	if err != nil {
		if found := os.IsNotExist(err); !found {
			t.Errorf("Error checking exported metadata in Svn: %s", err)
		}
	} else {
		t.Error("Error checking Svn metadata. It exists.")
	}
}

func TestSvnCheckLocal(t *testing.T) {
	// Verify repo.CheckLocal fails for non-SVN directories.
	// TestSvn is already checking on a valid repo
	tempDir, err := ioutil.TempDir("", "go-vcs-svn-tests")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	repo, _ := NewSvnRepo("", tempDir)
	if repo.CheckLocal() {
		t.Error("SVN CheckLocal does not identify non-SVN location")
	}

	// Test NewRepo when there's no local. This should simply provide a working
	// instance without error based on looking at the remote localtion.
	_, nrerr := NewRepo("https://github.com/Masterminds/VCSTestRepo/trunk", tempDir+"/VCSTestRepo")
	if nrerr != nil {
		t.Error(nrerr)
	}
}

func TestSvnPing(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-vcs-svn-tests")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	repo, err := NewSvnRepo("https://github.com/Masterminds/VCSTestRepo/trunk", tempDir)
	if err != nil {
		t.Error(err)
	}

	ping := repo.Ping()
	if !ping {
		t.Error("Svn unable to ping working repo")
	}

	repo, err = NewSvnRepo("https://github.com/Masterminds/ihopethisneverexistsbecauseitshouldnt", tempDir)
	if err != nil {
		t.Error(err)
	}

	ping = repo.Ping()
	if ping {
		t.Error("Svn got a ping response from when it should not have")
	}
}

func TestSvnInit(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-vcs-svn-tests")
	remoteDir := tempDir + string(os.PathSeparator) + "remoteDir"
	localDir := tempDir + string(os.PathSeparator) + "localDir"
	if err != nil {
		t.Error(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	repo, err := NewSvnRepo(remoteDir, localDir)
	if err != nil {
		t.Error(err)
	}

	err = repo.Init()
	if err != nil {
		t.Error(err)
	}

	err = repo.Get()
	if err != nil {
		t.Error(err)
	}

	v, err := repo.Version()
	if err != nil {
		t.Error(err)
	}
	if v != "0" {
		t.Errorf("Svn Init returns wrong version: %s", v)
	}
}
