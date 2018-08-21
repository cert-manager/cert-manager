package vcs

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func ExampleNewRepo() {
	remote := "https://github.com/Masterminds/vcs"
	local, _ := ioutil.TempDir("", "go-vcs")
	repo, _ := NewRepo(remote, local)
	// Returns: instance of GitRepo

	repo.Vcs()
	// Returns Git as this is a Git repo

	err := repo.Get()
	// Pulls down a repo, or a checkout in the case of SVN, and returns an
	// error if that didn't happen successfully.
	if err != nil {
		fmt.Println(err)
	}

	err = repo.UpdateVersion("master")
	// Checkouts out a specific version. In most cases this can be a commit id,
	// branch, or tag.
	if err != nil {
		fmt.Println(err)
	}
}

func TestTypeSwitch(t *testing.T) {

	// To test repo type switching we checkout as SVN and then try to get it as
	// a git repo afterwards.
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
	err = repo.Get()
	if err != nil {
		t.Errorf("Unable to checkout SVN repo for repo switching tests. Err was %s", err)
	}

	_, err = NewRepo("https://github.com/Masterminds/VCSTestRepo", tempDir+string(os.PathSeparator)+"VCSTestRepo")
	if err != ErrWrongVCS {
		t.Errorf("Not detecting repo switch from SVN to Git")
	}
}

func TestDepInstalled(t *testing.T) {
	i := depInstalled("git")
	if !i {
		t.Error("depInstalled not finding installed dep.")
	}

	i = depInstalled("thisreallyisntinstalled")
	if i {
		t.Error("depInstalled finding not installed dep.")
	}
}
