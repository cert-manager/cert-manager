package vcs

import (
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestVCSLookup(t *testing.T) {
	// TODO: Expand to make sure it detected the right vcs.
	urlList := map[string]struct {
		work bool
		t    Type
	}{
		"https://github.com/masterminds":                                   {work: false, t: Git},
		"https://github.com/Masterminds/VCSTestRepo":                       {work: true, t: Git},
		"https://bitbucket.org/mattfarina/testhgrepo":                      {work: true, t: Hg},
		"https://bitbucket.org/mattfarina/repo-does-not-exist":             {work: false, t: Hg},
		"https://bitbucket.org/mattfarina/private-repo-for-vcs-testing":    {work: false, t: Hg},
		"https://launchpad.net/govcstestbzrrepo/trunk":                     {work: true, t: Bzr},
		"https://launchpad.net/~mattfarina/+junk/mygovcstestbzrrepo":       {work: true, t: Bzr},
		"https://launchpad.net/~mattfarina/+junk/mygovcstestbzrrepo/trunk": {work: true, t: Bzr},
		"https://git.launchpad.net/govcstestgitrepo":                       {work: true, t: Git},
		"https://git.launchpad.net/~mattfarina/+git/mygovcstestgitrepo":    {work: true, t: Git},
		"https://hub.jazz.net/git/user1/pkgname":                           {work: true, t: Git},
		"https://hub.jazz.net/git/user1/pkgname/subpkg/subpkg/subpkg":      {work: true, t: Git},
		"https://hubs.jazz.net/git/user1/pkgname":                          {work: false, t: Git},
		"https://example.com/foo/bar.git":                                  {work: true, t: Git},
		"https://example.com/foo/bar.svn":                                  {work: true, t: Svn},
		"https://example.com/foo/bar/baz.bzr":                              {work: true, t: Bzr},
		"https://example.com/foo/bar/baz.hg":                               {work: true, t: Hg},
		"https://gopkg.in/tomb.v1":                                         {work: true, t: Git},
		"https://golang.org/x/net":                                         {work: true, t: Git},
		"https://speter.net/go/exp/math/dec/inf":                           {work: true, t: Git},
		"https://git.openstack.org/foo/bar":                                {work: true, t: Git},
		"git@github.com:Masterminds/vcs.git":                               {work: true, t: Git},
		"git@example.com:foo.git":                                          {work: true, t: Git},
		"ssh://hg@bitbucket.org/mattfarina/testhgrepo":                     {work: true, t: Hg},
		"git@bitbucket.org:mattfarina/glide-bitbucket-example.git":         {work: true, t: Git},
		"git+ssh://example.com/foo/bar":                                    {work: true, t: Git},
		"git://example.com/foo/bar":                                        {work: true, t: Git},
		"bzr+ssh://example.com/foo/bar":                                    {work: true, t: Bzr},
		"svn+ssh://example.com/foo/bar":                                    {work: true, t: Svn},
		"git@example.com:foo/bar":                                          {work: true, t: Git},
		"hg@example.com:foo/bar":                                           {work: true, t: Hg},
	}

	for u, c := range urlList {
		ty, _, err := detectVcsFromRemote(u)
		if err == nil && !c.work {
			t.Errorf("Error detecting VCS from URL(%s)", u)
		}

		if err == ErrCannotDetectVCS && c.work {
			t.Errorf("Error detecting VCS from URL(%s)", u)
		}

		if err != nil && c.work {
			t.Errorf("Error detecting VCS from URL(%s): %s", u, err)
		}

		if err != nil &&
			err != ErrCannotDetectVCS &&
			!strings.HasSuffix(err.Error(), "Not Found") &&
			!strings.HasSuffix(err.Error(), "Access Denied") &&
			!c.work {
			t.Errorf("Unexpected error returned (%s): %s", u, err)
		}

		if c.work && ty != c.t {
			t.Errorf("Incorrect VCS type returned(%s)", u)
		}
	}
}

func TestVCSFileLookup(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-vcs-file-lookup-tests")
	if err != nil {
		t.Error(err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Error(err)
		}
	}()

	_, err = exec.Command("git", "init", tempDir).CombinedOutput()
	if err != nil {
		t.Error(err)
	}

	// On Windows it should be file:// followed by /C:\for\bar. That / before
	// the drive needs to be included in testing.
	var pth string
	if runtime.GOOS == "windows" {
		pth = "file:///" + tempDir
	} else {
		pth = "file://" + tempDir
	}
	ty, _, err := detectVcsFromRemote(pth)

	if err != nil {
		t.Errorf("Unable to detect file:// path: %s", err)
	}

	if ty != Git {
		t.Errorf("Detected wrong type from file:// path. Found type %v", ty)
	}
}

func TestNotFound(t *testing.T) {
	_, _, err := detectVcsFromRemote("https://mattfarina.com/notfound")
	if err == nil || !strings.HasSuffix(err.Error(), " Not Found") {
		t.Errorf("Failed to find not found repo")
	}

	_, err = NewRepo("https://mattfarina.com/notfound", "")
	if err == nil || !strings.HasSuffix(err.Error(), " Not Found") {
		t.Errorf("Failed to find not found repo")
	}
}

func TestAccessDenied(t *testing.T) {
	_, _, err := detectVcsFromRemote("https://bitbucket.org/mattfarina/private-repo-for-vcs-testing")
	if err == nil || err.Error() != "Access Denied" {
		t.Errorf("Failed to detect access denied")
	}

	_, err = NewRepo("https://bitbucket.org/mattfarina/private-repo-for-vcs-testing", "")
	if err == nil || err.Error() != "Access Denied" {
		t.Errorf("Failed to detect access denied")
	}
}
