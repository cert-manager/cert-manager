// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dep

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode"

	"github.com/golang/dep/internal/test"
)

func discardLogger() *log.Logger {
	return log.New(ioutil.Discard, "", 0)
}

func TestCtx_ProjectImport(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir("src")

	h.Setenv("GOPATH", h.Path("."))
	depCtx := &Ctx{GOPATH: h.Path(".")}

	importPaths := []string{
		"github.com/pkg/errors",
		"my/silly/thing",
	}

	for _, want := range importPaths {
		fullpath := filepath.Join(depCtx.GOPATH, "src", want)
		h.TempDir(filepath.Join("src", want))
		got, err := depCtx.ImportForAbs(fullpath)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("expected %s, got %s", want, got)
		}
	}

	// test where it should return an error when directly within $GOPATH/src
	got, err := depCtx.ImportForAbs(filepath.Join(depCtx.GOPATH, "src"))
	if err == nil || !strings.Contains(err.Error(), "GOPATH/src") {
		t.Fatalf("should have gotten an error for use directly in GOPATH/src, but got %s", got)
	}

	// test where it should return an error
	got, err = depCtx.ImportForAbs("tra/la/la/la")
	if err == nil {
		t.Fatalf("should have gotten an error but did not for tra/la/la/la: %s", got)
	}
}

func TestAbsoluteProjectRoot(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir("src")
	h.Setenv("GOPATH", h.Path("."))
	depCtx := &Ctx{GOPATH: h.Path(".")}

	importPaths := map[string]bool{
		"github.com/pkg/errors": true,
		"my/silly/thing":        false,
	}

	for i, create := range importPaths {
		if create {
			h.TempDir(filepath.Join("src", i))
		}
	}

	for i, ok := range importPaths {
		got, err := depCtx.AbsForImport(i)
		if ok {
			h.Must(err)
			want := h.Path(filepath.Join("src", i))
			if got != want {
				t.Fatalf("expected %s, got %q", want, got)
			}
			continue
		}

		if err == nil {
			t.Fatalf("expected %s to fail", i)
		}
	}

	// test that a file fails
	h.TempFile("src/thing/thing.go", "hello world")
	_, err := depCtx.AbsForImport("thing/thing.go")
	if err == nil {
		t.Fatal("error should not be nil for a file found")
	}
}

func TestLoadProject(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir(filepath.Join("src", "test1", "sub"))
	h.TempFile(filepath.Join("src", "test1", ManifestName), "")
	h.TempFile(filepath.Join("src", "test1", LockName), `memo = "cdafe8641b28cd16fe025df278b0a49b9416859345d8b6ba0ace0272b74925ee"`)
	h.TempDir(filepath.Join("src", "test2", "sub"))
	h.TempFile(filepath.Join("src", "test2", ManifestName), "")

	var testcases = []struct {
		name string
		lock bool
		wd   string
	}{
		{"direct", true, filepath.Join("src", "test1")},
		{"ascending", true, filepath.Join("src", "test1", "sub")},
		{"without lock", false, filepath.Join("src", "test2")},
		{"ascending without lock", false, filepath.Join("src", "test2", "sub")},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &Ctx{
				Out: discardLogger(),
				Err: discardLogger(),
			}

			err := ctx.SetPaths(h.Path(tc.wd), h.Path("."))
			if err != nil {
				t.Fatalf("%+v", err)
			}

			p, err := ctx.LoadProject()
			switch {
			case err != nil:
				t.Fatalf("%s: LoadProject failed: %+v", tc.wd, err)
			case p.Manifest == nil:
				t.Fatalf("%s: Manifest file didn't load", tc.wd)
			case tc.lock && p.Lock == nil:
				t.Fatalf("%s: Lock file didn't load", tc.wd)
			case !tc.lock && p.Lock != nil:
				t.Fatalf("%s: Non-existent Lock file loaded", tc.wd)
			}
		})
	}
}

func TestExplicitRootProject(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir(filepath.Join("src", "test1", "sub"))
	h.TempFile(filepath.Join("src", "test1", ManifestName), "")
	h.TempFile(filepath.Join("src", "test1", LockName), `memo = "cdafe8641b28cd16fe025df278b0a49b9416859345d8b6ba0ace0272b74925ee"`)
	h.TempDir(filepath.Join("src", "test2", "sub"))
	h.TempFile(filepath.Join("src", "test2", ManifestName), "")
	h.Setenv("DEP_PROJECT_ROOT", "github.com/user/module")

	type tcase struct {
		name string
		lock bool
		wd   string
	}
	var testcases = []tcase{
		{"direct", true, filepath.Join("src", "test1")},
		{"ascending", true, filepath.Join("src", "test1", "sub")},
		{"without lock", false, filepath.Join("src", "test2")},
		{"ascending without lock", false, filepath.Join("src", "test2", "sub")},
	}

	tf := func(withGOPATH bool, tc tcase, t *testing.T) func(t *testing.T) {
		return func(t *testing.T) {
			ctx := &Ctx{
				Out: discardLogger(),
				Err: discardLogger(),
			}

			var err error
			if withGOPATH {
				err = ctx.SetPaths(h.Path(tc.wd), h.Path("."))
			} else {
				err = ctx.SetPaths(h.Path(tc.wd))
			}
			if err != nil {
				t.Fatalf("%+v", err)
			}
			ctx.ExplicitRoot = "github.com/user/module"

			p, err := ctx.LoadProject()
			switch {
			case err != nil:
				t.Fatalf("%s: LoadProject failed: %+v", tc.wd, err)
			case p.Manifest == nil:
				t.Fatalf("%s: Manifest file didn't load", tc.wd)
			case tc.lock && p.Lock == nil:
				t.Fatalf("%s: Lock file didn't load", tc.wd)
			case !tc.lock && p.Lock != nil:
				t.Fatalf("%s: Non-existent Lock file loaded", tc.wd)
			}
		}
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("within-GOPATH", tf(true, tc, t))
			t.Run("outside-GOPATH", tf(false, tc, t))
		})
	}
}

func TestLoadProjectNotFoundErrors(t *testing.T) {
	tg := test.NewHelper(t)
	defer tg.Cleanup()

	tg.TempDir("src")
	tg.TempDir("src/test1")
	tg.TempDir("src/test1/sub")
	tg.Setenv("GOPATH", tg.Path("."))

	var testcases = []struct {
		lock  bool
		start string
		path  string
	}{
		{true, filepath.Join("src", "test1"), ""},        //direct
		{true, filepath.Join("src", "test1", "sub"), ""}, //ascending
	}

	for _, testcase := range testcases {
		ctx := &Ctx{GOPATHs: []string{tg.Path(".")}, WorkingDir: tg.Path(testcase.start)}

		_, err := ctx.LoadProject()
		if err == nil {
			t.Errorf("%s: should have returned 'No Manifest Found' error", testcase.start)
		}
	}
}

func TestLoadProjectManifestParseError(t *testing.T) {
	tg := test.NewHelper(t)
	defer tg.Cleanup()

	tg.TempDir("src")
	tg.TempDir("src/test1")
	tg.TempFile(filepath.Join("src/test1", ManifestName), `[[constraint]]`)
	tg.TempFile(filepath.Join("src/test1", LockName), `memo = "cdafe8641b28cd16fe025df278b0a49b9416859345d8b6ba0ace0272b74925ee"\n\n[[projects]]`)
	tg.Setenv("GOPATH", tg.Path("."))

	path := filepath.Join("src", "test1")
	tg.Cd(tg.Path(path))

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal("failed to get working directory", err)
	}

	ctx := &Ctx{
		GOPATH:     tg.Path("."),
		WorkingDir: wd,
		Out:        discardLogger(),
		Err:        discardLogger(),
	}

	_, err = ctx.LoadProject()
	if err == nil {
		t.Fatal("should have returned 'Manifest Syntax' error")
	}
}

func TestLoadProjectLockParseError(t *testing.T) {
	tg := test.NewHelper(t)
	defer tg.Cleanup()

	tg.TempDir("src")
	tg.TempDir("src/test1")
	tg.TempFile(filepath.Join("src/test1", ManifestName), `[[constraint]]`)
	tg.TempFile(filepath.Join("src/test1", LockName), `memo = "cdafe8641b28cd16fe025df278b0a49b9416859345d8b6ba0ace0272b74925ee"\n\n[[projects]]`)
	tg.Setenv("GOPATH", tg.Path("."))

	path := filepath.Join("src", "test1")
	tg.Cd(tg.Path(path))

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal("failed to get working directory", err)
	}

	ctx := &Ctx{
		GOPATH:     tg.Path("."),
		WorkingDir: wd,
		Out:        discardLogger(),
		Err:        discardLogger(),
	}

	_, err = ctx.LoadProject()
	if err == nil {
		t.Fatal("should have returned 'Lock Syntax' error")
	}
}

func TestLoadProjectNoSrcDir(t *testing.T) {
	tg := test.NewHelper(t)
	defer tg.Cleanup()

	tg.TempDir("test1")
	tg.TempFile(filepath.Join("test1", ManifestName), `[[constraint]]`)
	tg.TempFile(filepath.Join("test1", LockName), `memo = "cdafe8641b28cd16fe025df278b0a49b9416859345d8b6ba0ace0272b74925ee"\n\n[[projects]]`)
	tg.Setenv("GOPATH", tg.Path("."))

	ctx := &Ctx{GOPATH: tg.Path(".")}
	path := filepath.Join("test1")
	tg.Cd(tg.Path(path))

	f, _ := os.OpenFile(filepath.Join(ctx.GOPATH, "src", "test1", LockName), os.O_WRONLY, os.ModePerm)
	defer f.Close()

	_, err := ctx.LoadProject()
	if err == nil {
		t.Fatal("should have returned 'Split Absolute Root' error (no 'src' dir present)")
	}
}

func TestLoadProjectGopkgFilenames(t *testing.T) {
	// We are trying to skip this test on file systems which are case-sensiive. We could
	// have used `fs.IsCaseSensitiveFilesystem` for this check. However, the code we are
	// testing also relies on `fs.IsCaseSensitiveFilesystem`. So a bug in
	// `fs.IsCaseSensitiveFilesystem` could prevent this test from being run. This is the
	// only scenario where we prefer the OS heuristic over doing the actual work of
	// validating filesystem case sensitivity via `fs.IsCaseSensitiveFilesystem`.
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("skip this test on non-Windows, non-macOS")
	}

	// Here we test that a manifest filename with incorrect case throws an error. Similar
	// error will also be thrown for the lock file as well which has been tested in
	// `project_test.go#TestCheckGopkgFilenames`. So not repeating here.

	h := test.NewHelper(t)
	defer h.Cleanup()

	invalidMfName := strings.ToLower(ManifestName)

	wd := filepath.Join("src", "test")
	h.TempFile(filepath.Join(wd, invalidMfName), "")

	ctx := &Ctx{
		Out: discardLogger(),
		Err: discardLogger(),
	}

	err := ctx.SetPaths(h.Path(wd), h.Path("."))
	if err != nil {
		t.Fatalf("%+v", err)
	}

	_, err = ctx.LoadProject()

	if err == nil {
		t.Fatal("should have returned 'Manifest Filename' error")
	}

	expectedErrMsg := fmt.Sprintf(
		"manifest filename %q does not match %q",
		invalidMfName, ManifestName,
	)

	if err.Error() != expectedErrMsg {
		t.Fatalf("unexpected error: %+v", err)
	}
}

// TestCaseInsensitive is test for Windows. This should work even though set
// difference letter cases in GOPATH.
func TestCaseInsensitiveGOPATH(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skip this test on non-Windows")
	}

	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir("src")
	h.TempDir("src/test1")
	h.TempFile(filepath.Join("src/test1", ManifestName), `
	[[constraint]]
		name = "github.com/foo/bar"
		branch = "master"`)

	// Shuffle letter case
	rs := []rune(strings.ToLower(h.Path(".")))
	for i, r := range rs {
		if unicode.IsLower(r) {
			rs[i] = unicode.ToUpper(r)
		} else {
			rs[i] = unicode.ToLower(r)
		}
	}
	gopath := string(rs)
	h.Setenv("GOPATH", gopath)
	wd := h.Path("src/test1")

	depCtx := &Ctx{}
	if err := depCtx.SetPaths(wd, gopath); err != nil {
		t.Fatal(err)
	}
	if _, err := depCtx.LoadProject(); err != nil {
		t.Fatal(err)
	}

	ip := "github.com/pkg/errors"
	fullpath := filepath.Join(depCtx.GOPATH, "src", ip)
	h.TempDir(filepath.Join("src", ip))
	pr, err := depCtx.ImportForAbs(fullpath)
	if err != nil {
		t.Fatal(err)
	}
	if pr != ip {
		t.Fatalf("expected %s, got %s", ip, pr)
	}
}

func TestDetectProjectGOPATH(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir(filepath.Join("sym", "symlink"))
	h.TempDir(filepath.Join("go", "src", "sym", "path"))
	h.TempDir(filepath.Join("go", "src", "real", "path"))
	h.TempDir(filepath.Join("go-two", "src", "real", "path"))
	h.TempDir(filepath.Join("go-two", "src", "sym"))

	ctx := &Ctx{
		GOPATHs: []string{h.Path("go"), h.Path("go-two")},
	}

	testcases := []struct {
		name         string
		root         string
		resolvedRoot string
		GOPATH       string
		expectErr    bool
	}{
		{
			name:         "project-with-no-AbsRoot",
			root:         "",
			resolvedRoot: filepath.Join(ctx.GOPATHs[0], "src", "real", "path"),
			expectErr:    true,
		},
		{
			name:         "project-with-no-ResolvedAbsRoot",
			root:         filepath.Join(ctx.GOPATHs[0], "src", "real", "path"),
			resolvedRoot: "",
			expectErr:    true,
		},
		{
			name:         "AbsRoot-is-not-within-any-GOPATH",
			root:         filepath.Join(h.Path("."), "src", "real", "path"),
			resolvedRoot: filepath.Join(h.Path("."), "src", "real", "path"),
			expectErr:    true,
		},
		{
			name:         "neither-AbsRoot-nor-ResolvedAbsRoot-are-in-any-GOPATH",
			root:         filepath.Join(h.Path("."), "src", "sym", "path"),
			resolvedRoot: filepath.Join(h.Path("."), "src", "real", "path"),
			expectErr:    true,
		},
		{
			name:         "both-AbsRoot-and-ResolvedAbsRoot-are-in-the-same-GOPATH",
			root:         filepath.Join(ctx.GOPATHs[0], "src", "sym", "path"),
			resolvedRoot: filepath.Join(ctx.GOPATHs[0], "src", "real", "path"),
			expectErr:    true,
		},
		{
			name:         "AbsRoot-and-ResolvedAbsRoot-are-each-within-a-different-GOPATH",
			root:         filepath.Join(ctx.GOPATHs[0], "src", "sym", "path"),
			resolvedRoot: filepath.Join(ctx.GOPATHs[1], "src", "real", "path"),
			expectErr:    true,
		},
		{
			name:         "AbsRoot-is-not-a-symlink",
			root:         filepath.Join(ctx.GOPATHs[0], "src", "real", "path"),
			resolvedRoot: filepath.Join(ctx.GOPATHs[0], "src", "real", "path"),
			GOPATH:       ctx.GOPATHs[0],
		},
		{
			name:         "AbsRoot-is-a-symlink-to-ResolvedAbsRoot",
			root:         filepath.Join(h.Path("."), "sym", "symlink"),
			resolvedRoot: filepath.Join(ctx.GOPATHs[0], "src", "real", "path"),
			GOPATH:       ctx.GOPATHs[0],
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			project := &Project{
				AbsRoot:         tc.root,
				ResolvedAbsRoot: tc.resolvedRoot,
			}

			GOPATH, err := ctx.DetectProjectGOPATH(project)
			if !tc.expectErr && err != nil {
				t.Fatalf("%+v", err)
			} else if tc.expectErr && err == nil {
				t.Fatalf("expected an error, got nil and gopath %s", GOPATH)
			}
			if GOPATH != tc.GOPATH {
				t.Errorf("expected GOPATH %s, got %s", tc.GOPATH, GOPATH)
			}
		})
	}
}

func TestDetectGOPATH(t *testing.T) {
	th := test.NewHelper(t)
	defer th.Cleanup()

	th.TempDir(filepath.Join("code", "src", "github.com", "username", "package"))
	th.TempDir(filepath.Join("go", "src", "github.com", "username", "package"))
	th.TempDir(filepath.Join("gotwo", "src", "github.com", "username", "package"))
	th.TempDir(filepath.Join("gothree", "sep", "src", "github.com", "username", "package"))

	sep := string(os.PathSeparator)

	ctx := &Ctx{GOPATHs: []string{
		th.Path("go"),
		th.Path("gotwo"),
		th.Path("gothree") + sep + sep + "sep",
	}}

	testcases := []struct {
		GOPATH string
		path   string
		err    bool
	}{
		{th.Path("go"), th.Path(filepath.Join("go", "src", "github.com", "username", "package")), false},
		{th.Path("go"), th.Path(filepath.Join("go", "src", "github.com", "username", "package")), false},
		{th.Path("gotwo"), th.Path(filepath.Join("gotwo", "src", "github.com", "username", "package")), false},
		{th.Path(filepath.Join("gothree", "sep")),
			th.Path(filepath.Join("gothree", "sep", "src", "github.com", "username", "package")), false},
		{"", th.Path(filepath.Join("code", "src", "github.com", "username", "package")), true},
	}

	for _, tc := range testcases {
		GOPATH, err := ctx.detectGOPATH(tc.path)
		if tc.err && err == nil {
			t.Error("expected error but got none")
		}
		if GOPATH != tc.GOPATH {
			t.Errorf("expected GOPATH to be %s, got %s", tc.GOPATH, GOPATH)
		}
	}
}

func TestDepCachedir(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir("cache")
	// Create the directory for default cachedir location.
	h.TempDir(filepath.Join("go", "pkg", "dep"))

	testCachedir := h.Path("cache")
	gopath := h.Path("go")
	discardLgr := discardLogger()

	cases := []struct {
		cachedir     string
		wantCachedir string
	}{
		// If `Cachedir` is not set in the context, it should use `$GOPATH/pkg/dep`.
		{cachedir: "", wantCachedir: h.Path(filepath.Join("go", "pkg", "dep"))},
		// If `Cachedir` is set in the context, it should use that.
		{cachedir: testCachedir, wantCachedir: testCachedir},
	}

	for _, c := range cases {
		ctx := &Ctx{
			GOPATH:   gopath,
			Cachedir: c.cachedir,
			Out:      discardLgr,
			Err:      discardLgr,
		}
		sm, err := ctx.SourceManager()
		h.Must(err)
		defer sm.Release()

		if sm.Cachedir() != c.wantCachedir {
			t.Errorf("expected cachedir to be %s, got %s", c.wantCachedir, sm.Cachedir())
		}
	}
}
