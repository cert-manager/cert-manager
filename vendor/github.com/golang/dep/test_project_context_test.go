// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dep

import (
	"path/filepath"

	"github.com/golang/dep/gps"
	"github.com/golang/dep/internal/test"
	"github.com/pkg/errors"
)

// TestProjectContext groups together test project files and helps test them
type TestProjectContext struct {
	h              *test.Helper
	tempDir        string // Full path to the temp directory
	tempProjectDir string // Relative path of the project under the temp directory

	Context       *Ctx
	Project       *Project
	SourceManager gps.SourceManager
}

// NewTestProjectContext creates a new on-disk test project
func NewTestProjectContext(h *test.Helper, projectName string) *TestProjectContext {
	pc := &TestProjectContext{h: h}

	// Create the test project directory
	pc.tempProjectDir = filepath.Join("src", projectName)
	h.TempDir(pc.tempProjectDir)
	pc.tempDir = h.Path(".")
	pc.Project = &Project{AbsRoot: filepath.Join(pc.tempDir, pc.tempProjectDir)}
	h.Cd(pc.Project.AbsRoot)
	h.Setenv("GOPATH", pc.tempDir)

	// Set up a Source Manager
	var err error
	pc.Context = &Ctx{
		GOPATH: pc.tempDir,
		Out:    discardLogger(),
		Err:    discardLogger(),
	}
	pc.SourceManager, err = pc.Context.SourceManager()
	h.Must(errors.Wrap(err, "Unable to create a SourceManager"))

	return pc
}

// CopyFile copies a file from the testdata directory into the project
// projectPath is the destination file path, relative to the project directory
// testdataPath is the source path, relative to the testdata directory
func (pc *TestProjectContext) CopyFile(projectPath string, testdataPath string) string {
	path := filepath.Join(pc.tempProjectDir, projectPath)
	pc.h.TempCopy(path, testdataPath)
	return path
}

func (pc *TestProjectContext) Load() {
	// TODO(carolynvs): Can't use Ctx.LoadProject until dep doesn't require a manifest at the project root or it also looks for lock
	var err error
	var m *Manifest
	mp := pc.getManifestPath()
	if pc.h.Exist(mp) {
		mf := pc.h.GetFile(mp)
		defer mf.Close()
		var warns []error
		m, warns, err = readManifest(mf)
		for _, warn := range warns {
			pc.Context.Err.Printf("dep: WARNING: %v\n", warn)
		}
		pc.h.Must(errors.Wrapf(err, "Unable to read manifest at %s", mp))
	}
	var l *Lock
	lp := pc.getLockPath()
	if pc.h.Exist(lp) {
		lf := pc.h.GetFile(lp)
		defer lf.Close()
		l, err = readLock(lf)
		pc.h.Must(errors.Wrapf(err, "Unable to read lock at %s", lp))
	}
	pc.Project.Manifest = m
	pc.Project.Lock = l
}

// GetLockPath returns the full path to the lock
func (pc *TestProjectContext) getLockPath() string {
	return filepath.Join(pc.Project.AbsRoot, LockName)
}

// GetManifestPath returns the full path to the manifest
func (pc *TestProjectContext) getManifestPath() string {
	return filepath.Join(pc.Project.AbsRoot, ManifestName)
}

// GetVendorPath returns the full path to the vendor directory
func (pc *TestProjectContext) getVendorPath() string {
	return filepath.Join(pc.Project.AbsRoot, "vendor")
}

// LockShouldMatchGolden returns an error when the lock does not match the golden lock.
// goldenLockPath is the path to the golden lock file relative to the testdata directory
// Updates the golden file when -UpdateGolden flag is present.
func (pc *TestProjectContext) LockShouldMatchGolden(goldenLockPath string) error {
	got := pc.h.ReadLock()
	return pc.ShouldMatchGolden(goldenLockPath, got)
}

// LockShouldNotExist returns an error when the lock exists.
func (pc *TestProjectContext) LockShouldNotExist() error {
	return pc.h.ShouldNotExist(pc.getLockPath())
}

// ManifestShouldMatchGolden returns an error when the manifest does not match the golden manifest.
// goldenManifestPath is the path to the golden manifest file, relative to the testdata directory
// Updates the golden file when -UpdateGolden flag is present
func (pc *TestProjectContext) ManifestShouldMatchGolden(goldenManifestPath string) error {
	got := pc.h.ReadManifest()
	return pc.ShouldMatchGolden(goldenManifestPath, got)
}

// ManifestShouldNotExist returns an error when the lock exists.
func (pc *TestProjectContext) ManifestShouldNotExist() error {
	return pc.h.ShouldNotExist(pc.getManifestPath())
}

// ShouldMatchGolden returns an error when a file does not match the golden file.
// goldenFile is the path to the golden file, relative to the testdata directory
// Updates the golden file when -UpdateGolden flag is present
func (pc *TestProjectContext) ShouldMatchGolden(goldenFile string, got string) error {
	want := pc.h.GetTestFileString(goldenFile)
	if want != got {
		if *test.UpdateGolden {
			if err := pc.h.WriteTestFile(goldenFile, got); err != nil {
				return errors.Wrapf(err, "Unable to write updated golden file %s", goldenFile)
			}
		} else {
			return errors.Errorf("expected %s, got %s", want, got)
		}
	}

	return nil
}

// VendorShouldExist returns an error when the vendor directory does not exist.
func (pc *TestProjectContext) VendorShouldExist() error {
	return pc.h.ShouldExist(pc.getVendorPath())
}

// VendorFileShouldExist returns an error when the specified file does not exist in vendor.
// filePath is the relative path to the file within vendor
func (pc *TestProjectContext) VendorFileShouldExist(filePath string) error {
	fullPath := filepath.Join(pc.getVendorPath(), filePath)
	return pc.h.ShouldExist(fullPath)
}

// VendorShouldNotExist returns an error when the vendor directory exists.
func (pc *TestProjectContext) VendorShouldNotExist() error {
	return pc.h.ShouldNotExist(pc.getVendorPath())
}

// Release cleans up after test objects created by this instance
func (pc *TestProjectContext) Release() {
	if pc.SourceManager != nil {
		pc.SourceManager.Release()
	}
}
