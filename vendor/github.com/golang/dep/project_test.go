// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dep

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/golang/dep/gps"
	"github.com/golang/dep/internal/test"
)

func TestFindRoot(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(wd, "testdata", "rootfind")
	got1, err := findProjectRoot(want)
	if err != nil {
		t.Errorf("Unexpected error while finding root: %s", err)
	} else if want != got1 {
		t.Errorf("findProjectRoot directly on root dir should have found %s, got %s", want, got1)
	}

	got2, err := findProjectRoot(filepath.Join(want, "subdir"))
	if err != nil {
		t.Errorf("Unexpected error while finding root: %s", err)
	} else if want != got2 {
		t.Errorf("findProjectRoot on subdir should have found %s, got %s", want, got2)
	}

	got3, err := findProjectRoot(filepath.Join(want, "nonexistent"))
	if err != nil {
		t.Errorf("Unexpected error while finding root: %s", err)
	} else if want != got3 {
		t.Errorf("findProjectRoot on nonexistent subdir should still work and give %s, got %s", want, got3)
	}

	root := "/"
	p, err := findProjectRoot(root)
	if p != "" {
		t.Errorf("findProjectRoot with path %s returned non empty string: %s", root, p)
	}
	if err != errProjectNotFound {
		t.Errorf("findProjectRoot want: %#v got: %#v", errProjectNotFound, err)
	}

	// The following test does not work on windows because syscall.Stat does not
	// return a "not a directory" error.
	if runtime.GOOS != "windows" {
		got4, err := findProjectRoot(filepath.Join(want, ManifestName))
		if err == nil {
			t.Errorf("Should have err'd when trying subdir of file, but returned %s", got4)
		}
	}
}

func TestCheckGopkgFilenames(t *testing.T) {
	// We are trying to skip this test on file systems which are case-sensiive. We could
	// have used `fs.IsCaseSensitiveFilesystem` for this check. However, the code we are
	// testing also relies on `fs.IsCaseSensitiveFilesystem`. So a bug in
	// `fs.IsCaseSensitiveFilesystem` could prevent this test from being run. This is the
	// only scenario where we prefer the OS heuristic over doing the actual work of
	// validating filesystem case sensitivity via `fs.IsCaseSensitiveFilesystem`.
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("skip this test on non-Windows, non-macOS")
	}

	errMsgFor := func(filetype, filename string) func(string) string {
		return func(name string) string {
			return fmt.Sprintf("%s filename %q does not match %q", filetype, name, filename)
		}
	}

	manifestErrMsg := errMsgFor("manifest", ManifestName)
	lockErrMsg := errMsgFor("lock", LockName)

	invalidMfName := strings.ToLower(ManifestName)
	invalidLfName := strings.ToLower(LockName)

	cases := []struct {
		wantErr     bool
		createFiles []string
		wantErrMsg  string
	}{
		// No error should be returned when the project contains a valid manifest file
		// but no lock file.
		{false, []string{ManifestName}, ""},
		// No error should be returned when the project contains a valid manifest file as
		// well as a valid lock file.
		{false, []string{ManifestName, LockName}, ""},
		// Error indicating the project was not found should be returned if a manifest
		// file is not found.
		{true, nil, errProjectNotFound.Error()},
		// Error should be returned if the project has a manifest file with invalid name
		// but no lock file.
		{true, []string{invalidMfName}, manifestErrMsg(invalidMfName)},
		// Error should be returned if the project has a valid manifest file and an
		// invalid lock file.
		{true, []string{ManifestName, invalidLfName}, lockErrMsg(invalidLfName)},
	}

	for _, c := range cases {
		h := test.NewHelper(t)
		defer h.Cleanup()

		// Create a temporary directory which we will use as the project folder.
		h.TempDir("")
		tmpPath := h.Path(".")

		// Create any files that are needed for the test before invoking
		// `checkGopkgFilenames`.
		for _, file := range c.createFiles {
			h.TempFile(file, "")
		}
		err := checkGopkgFilenames(tmpPath)

		if c.wantErr {
			if err == nil {
				// We were expecting an error but did not get one.
				t.Fatalf("unexpected error message: \n\t(GOT) nil\n\t(WNT) %s", c.wantErrMsg)
			} else if err.Error() != c.wantErrMsg {
				// We got an error but it is not the one we were expecting.
				t.Fatalf("unexpected error message: \n\t(GOT) %s\n\t(WNT) %s", err.Error(), c.wantErrMsg)
			}
		} else if err != nil {
			// Error was not expected but still we got one
			t.Fatalf("unexpected error message: \n\t(GOT) %+v", err)
		}
	}
}

func TestProjectMakeParams(t *testing.T) {
	m := NewManifest()
	m.Ignored = []string{"ignoring this"}

	p := Project{
		AbsRoot:    "someroot",
		ImportRoot: gps.ProjectRoot("Some project root"),
		Manifest:   m,
		Lock:       &Lock{},
	}
	p.ChangedLock = p.Lock

	solveParam := p.MakeParams()

	if solveParam.Manifest != p.Manifest {
		t.Error("makeParams() returned gps.SolveParameters with incorrect Manifest")
	}

	if solveParam.Lock != p.Lock {
		t.Error("makeParams() returned gps.SolveParameters with incorrect Lock")
	}
}

func TestBackupVendor(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	pc := NewTestProjectContext(h, "vendorbackupproject")
	defer pc.Release()

	dummyFile := filepath.Join("vendor", "badinput_fileroot")
	pc.CopyFile(dummyFile, "txn_writer/badinput_fileroot")
	pc.Load()

	if err := pc.VendorShouldExist(); err != nil {
		t.Fatal(err)
	}

	// Create a backup
	wantName := "_vendor-sfx"
	vendorbak, err := BackupVendor("vendor", "sfx")
	if err != nil {
		t.Fatal(err)
	}

	if vendorbak != wantName {
		t.Fatalf("Vendor backup name is not as expected: \n\t(GOT) %v\n\t(WNT) %v", vendorbak, wantName)
	}

	if err = pc.h.ShouldExist(vendorbak); err != nil {
		t.Fatal(err)
	}

	if err = pc.h.ShouldExist(vendorbak + string(filepath.Separator) + "badinput_fileroot"); err != nil {
		t.Fatal(err)
	}

	// Should return error on creating backup with existing filename
	vendorbak, err = BackupVendor("vendor", "sfx")

	if err != errVendorBackupFailed {
		t.Fatalf("Vendor backup error is not as expected: \n\t(GOT) %v\n\t(WNT) %v", err, errVendorBackupFailed)
	}

	if vendorbak != "" {
		t.Fatalf("Vendor backup name is not as expected: \n\t(GOT) %v\n\t(WNT) %v", vendorbak, "")
	}

	// Delete vendor
	if err = os.RemoveAll("vendor"); err != nil {
		t.Fatal(err)
	}

	// Should return empty backup file name when no vendor exists
	vendorbak, err = BackupVendor("vendor", "sfx")
	if err != nil {
		t.Fatal(err)
	}

	if vendorbak != "" {
		t.Fatalf("Vendor backup name is not as expected: \n\t(GOT) %v\n\t(WNT) %v", vendorbak, "")
	}
}
