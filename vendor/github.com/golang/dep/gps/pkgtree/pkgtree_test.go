// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkgtree

import (
	"fmt"
	"go/build"
	"go/scanner"
	"go/token"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/golang/dep/gps/paths"
	"github.com/golang/dep/internal/fs"
	_ "github.com/golang/dep/internal/test" // DO NOT REMOVE, allows go test ./... -update to work
)

// PackageTree.ToReachMap() uses an easily separable algorithm, wmToReach(),
// to turn a discovered set of packages and their imports into a proper pair of
// internal and external reach maps.
//
// That algorithm is purely symbolic (no filesystem interaction), and thus is
// easy to test. This is that test.
func TestWorkmapToReach(t *testing.T) {
	empty := func() map[string]bool {
		return make(map[string]bool)
	}

	table := map[string]struct {
		workmap  map[string]wm
		rm       ReachMap
		em       map[string]*ProblemImportError
		backprop bool
	}{
		"single": {
			workmap: map[string]wm{
				"foo": {
					ex: empty(),
					in: empty(),
				},
			},
			rm: ReachMap{
				"foo": {},
			},
		},
		"no external": {
			workmap: map[string]wm{
				"foo": {
					ex: empty(),
					in: empty(),
				},
				"foo/bar": {
					ex: empty(),
					in: empty(),
				},
			},
			rm: ReachMap{
				"foo":     {},
				"foo/bar": {},
			},
		},
		"no external with subpkg": {
			workmap: map[string]wm{
				"foo": {
					ex: empty(),
					in: map[string]bool{
						"foo/bar": true,
					},
				},
				"foo/bar": {
					ex: empty(),
					in: empty(),
				},
			},
			rm: ReachMap{
				"foo": {
					Internal: []string{"foo/bar"},
				},
				"foo/bar": {},
			},
		},
		"simple base transitive": {
			workmap: map[string]wm{
				"foo": {
					ex: empty(),
					in: map[string]bool{
						"foo/bar": true,
					},
				},
				"foo/bar": {
					ex: map[string]bool{
						"baz": true,
					},
					in: empty(),
				},
			},
			rm: ReachMap{
				"foo": {
					External: []string{"baz"},
					Internal: []string{"foo/bar"},
				},
				"foo/bar": {
					External: []string{"baz"},
				},
			},
		},
		"missing package is poison": {
			workmap: map[string]wm{
				"A": {
					ex: map[string]bool{
						"B/foo": true,
					},
					in: map[string]bool{
						"A/foo": true, // missing
						"A/bar": true,
					},
				},
				"A/bar": {
					ex: map[string]bool{
						"B/baz": true,
					},
					in: empty(),
				},
			},
			rm: ReachMap{
				"A/bar": {
					External: []string{"B/baz"},
				},
			},
			em: map[string]*ProblemImportError{
				"A": {
					ImportPath: "A",
					Cause:      []string{"A/foo"},
					Err:        missingPkgErr("A/foo"),
				},
			},
			backprop: true,
		},
		"transitive missing package is poison": {
			workmap: map[string]wm{
				"A": {
					ex: map[string]bool{
						"B/foo": true,
					},
					in: map[string]bool{
						"A/foo":  true, // transitively missing
						"A/quux": true,
					},
				},
				"A/foo": {
					ex: map[string]bool{
						"C/flugle": true,
					},
					in: map[string]bool{
						"A/bar": true, // missing
					},
				},
				"A/quux": {
					ex: map[string]bool{
						"B/baz": true,
					},
					in: empty(),
				},
			},
			rm: ReachMap{
				"A/quux": {
					External: []string{"B/baz"},
				},
			},
			em: map[string]*ProblemImportError{
				"A": {
					ImportPath: "A",
					Cause:      []string{"A/foo", "A/bar"},
					Err:        missingPkgErr("A/bar"),
				},
				"A/foo": {
					ImportPath: "A/foo",
					Cause:      []string{"A/bar"},
					Err:        missingPkgErr("A/bar"),
				},
			},
			backprop: true,
		},
		"err'd package is poison": {
			workmap: map[string]wm{
				"A": {
					ex: map[string]bool{
						"B/foo": true,
					},
					in: map[string]bool{
						"A/foo": true, // err'd
						"A/bar": true,
					},
				},
				"A/foo": {
					err: fmt.Errorf("err pkg"),
				},
				"A/bar": {
					ex: map[string]bool{
						"B/baz": true,
					},
					in: empty(),
				},
			},
			rm: ReachMap{
				"A/bar": {
					External: []string{"B/baz"},
				},
			},
			em: map[string]*ProblemImportError{
				"A": {
					ImportPath: "A",
					Cause:      []string{"A/foo"},
					Err:        fmt.Errorf("err pkg"),
				},
				"A/foo": {
					ImportPath: "A/foo",
					Err:        fmt.Errorf("err pkg"),
				},
			},
			backprop: true,
		},
		"transitive err'd package is poison": {
			workmap: map[string]wm{
				"A": {
					ex: map[string]bool{
						"B/foo": true,
					},
					in: map[string]bool{
						"A/foo":  true, // transitively err'd
						"A/quux": true,
					},
				},
				"A/foo": {
					ex: map[string]bool{
						"C/flugle": true,
					},
					in: map[string]bool{
						"A/bar": true, // err'd
					},
				},
				"A/bar": {
					err: fmt.Errorf("err pkg"),
				},
				"A/quux": {
					ex: map[string]bool{
						"B/baz": true,
					},
					in: empty(),
				},
			},
			rm: ReachMap{
				"A/quux": {
					External: []string{"B/baz"},
				},
			},
			em: map[string]*ProblemImportError{
				"A": {
					ImportPath: "A",
					Cause:      []string{"A/foo", "A/bar"},
					Err:        fmt.Errorf("err pkg"),
				},
				"A/foo": {
					ImportPath: "A/foo",
					Cause:      []string{"A/bar"},
					Err:        fmt.Errorf("err pkg"),
				},
				"A/bar": {
					ImportPath: "A/bar",
					Err:        fmt.Errorf("err pkg"),
				},
			},
			backprop: true,
		},
		"transitive err'd package no backprop": {
			workmap: map[string]wm{
				"A": {
					ex: map[string]bool{
						"B/foo": true,
					},
					in: map[string]bool{
						"A/foo":  true, // transitively err'd
						"A/quux": true,
					},
				},
				"A/foo": {
					ex: map[string]bool{
						"C/flugle": true,
					},
					in: map[string]bool{
						"A/bar": true, // err'd
					},
				},
				"A/bar": {
					err: fmt.Errorf("err pkg"),
				},
				"A/quux": {
					ex: map[string]bool{
						"B/baz": true,
					},
					in: empty(),
				},
			},
			rm: ReachMap{
				"A": {
					Internal: []string{"A/bar", "A/foo", "A/quux"},
					//Internal: []string{"A/foo", "A/quux"},
					External: []string{"B/baz", "B/foo", "C/flugle"},
				},
				"A/foo": {
					Internal: []string{"A/bar"},
					External: []string{"C/flugle"},
				},
				"A/quux": {
					External: []string{"B/baz"},
				},
			},
			em: map[string]*ProblemImportError{
				"A/bar": {
					ImportPath: "A/bar",
					Err:        fmt.Errorf("err pkg"),
				},
			},
		},
		// The following tests are mostly about regressions and weeding out
		// weird assumptions
		"internal diamond": {
			workmap: map[string]wm{
				"A": {
					ex: map[string]bool{
						"B/foo": true,
					},
					in: map[string]bool{
						"A/foo": true,
						"A/bar": true,
					},
				},
				"A/foo": {
					ex: map[string]bool{
						"C": true,
					},
					in: map[string]bool{
						"A/quux": true,
					},
				},
				"A/bar": {
					ex: map[string]bool{
						"D": true,
					},
					in: map[string]bool{
						"A/quux": true,
					},
				},
				"A/quux": {
					ex: map[string]bool{
						"B/baz": true,
					},
					in: empty(),
				},
			},
			rm: ReachMap{
				"A": {
					External: []string{
						"B/baz",
						"B/foo",
						"C",
						"D",
					},
					Internal: []string{
						"A/bar",
						"A/foo",
						"A/quux",
					},
				},
				"A/foo": {
					External: []string{
						"B/baz",
						"C",
					},
					Internal: []string{
						"A/quux",
					},
				},
				"A/bar": {
					External: []string{
						"B/baz",
						"D",
					},
					Internal: []string{
						"A/quux",
					},
				},
				"A/quux": {
					External: []string{"B/baz"},
				},
			},
		},
		"rootmost gets imported": {
			workmap: map[string]wm{
				"A": {
					ex: map[string]bool{
						"B": true,
					},
					in: empty(),
				},
				"A/foo": {
					ex: map[string]bool{
						"C": true,
					},
					in: map[string]bool{
						"A": true,
					},
				},
			},
			rm: ReachMap{
				"A": {
					External: []string{"B"},
				},
				"A/foo": {
					External: []string{
						"B",
						"C",
					},
					Internal: []string{
						"A",
					},
				},
			},
		},
	}

	for name, fix := range table {
		name, fix := name, fix
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Avoid erroneous errors by initializing the fixture's error map if
			// needed
			if fix.em == nil {
				fix.em = make(map[string]*ProblemImportError)
			}

			rm, em := wmToReach(fix.workmap, fix.backprop)
			if !reflect.DeepEqual(rm, fix.rm) {
				//t.Error(pretty.Sprintf("wmToReach(%q): Did not get expected reach map:\n\t(GOT): %s\n\t(WNT): %s", name, rm, fix.rm))
				t.Errorf("Did not get expected reach map:\n\t(GOT): %s\n\t(WNT): %s", rm, fix.rm)
			}
			if !reflect.DeepEqual(em, fix.em) {
				//t.Error(pretty.Sprintf("wmToReach(%q): Did not get expected error map:\n\t(GOT): %# v\n\t(WNT): %# v", name, em, fix.em))
				t.Errorf("Did not get expected error map:\n\t(GOT): %v\n\t(WNT): %v", em, fix.em)
			}
		})
	}
}

func TestListPackagesNoDir(t *testing.T) {
	out, err := ListPackages(filepath.Join(getTestdataRootDir(t), "notexist"), "notexist")
	if err == nil {
		t.Error("ListPackages should have errored on pointing to a nonexistent dir")
	}
	if !reflect.DeepEqual(PackageTree{}, out) {
		t.Error("should've gotten back an empty PackageTree")
	}
}

func TestListPackages(t *testing.T) {
	srcdir := filepath.Join(getTestdataRootDir(t), "src")
	j := func(s ...string) string {
		return filepath.Join(srcdir, filepath.Join(s...))
	}

	table := map[string]struct {
		fileRoot   string
		importRoot string
		out        PackageTree
		err        error
	}{
		"empty": {
			fileRoot:   j("empty"),
			importRoot: "empty",
			out: PackageTree{
				ImportRoot: "empty",
				Packages: map[string]PackageOrErr{
					"empty": {
						Err: &build.NoGoError{
							Dir: j("empty"),
						},
					},
				},
			},
		},
		"code only": {
			fileRoot:   j("simple"),
			importRoot: "simple",
			out: PackageTree{
				ImportRoot: "simple",
				Packages: map[string]PackageOrErr{
					"simple": {
						P: Package{
							ImportPath:  "simple",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
							},
						},
					},
				},
			},
		},
		"impose import path": {
			fileRoot:   j("simple"),
			importRoot: "arbitrary",
			out: PackageTree{
				ImportRoot: "arbitrary",
				Packages: map[string]PackageOrErr{
					"arbitrary": {
						P: Package{
							ImportPath:  "arbitrary",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
							},
						},
					},
				},
			},
		},
		"test only": {
			fileRoot:   j("t"),
			importRoot: "simple",
			out: PackageTree{
				ImportRoot: "simple",
				Packages: map[string]PackageOrErr{
					"simple": {
						P: Package{
							ImportPath:  "simple",
							CommentPath: "",
							Name:        "simple",
							Imports:     []string{},
							TestImports: []string{
								"math/rand",
								"strconv",
							},
						},
					},
				},
			},
		},
		"xtest only": {
			fileRoot:   j("xt"),
			importRoot: "simple",
			out: PackageTree{
				ImportRoot: "simple",
				Packages: map[string]PackageOrErr{
					"simple": {
						P: Package{
							ImportPath:  "simple",
							CommentPath: "",
							Name:        "simple",
							Imports:     []string{},
							TestImports: []string{
								"sort",
								"strconv",
							},
						},
					},
				},
			},
		},
		"code and test": {
			fileRoot:   j("simplet"),
			importRoot: "simple",
			out: PackageTree{
				ImportRoot: "simple",
				Packages: map[string]PackageOrErr{
					"simple": {
						P: Package{
							ImportPath:  "simple",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
							},
							TestImports: []string{
								"math/rand",
								"strconv",
							},
						},
					},
				},
			},
		},
		"code and xtest": {
			fileRoot:   j("simplext"),
			importRoot: "simple",
			out: PackageTree{
				ImportRoot: "simple",
				Packages: map[string]PackageOrErr{
					"simple": {
						P: Package{
							ImportPath:  "simple",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
							},
							TestImports: []string{
								"sort",
								"strconv",
							},
						},
					},
				},
			},
		},
		"code, test, xtest": {
			fileRoot:   j("simpleallt"),
			importRoot: "simple",
			out: PackageTree{
				ImportRoot: "simple",
				Packages: map[string]PackageOrErr{
					"simple": {
						P: Package{
							ImportPath:  "simple",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
							},
							TestImports: []string{
								"math/rand",
								"sort",
								"strconv",
							},
						},
					},
				},
			},
		},
		"one pkg multifile": {
			fileRoot:   j("m1p"),
			importRoot: "m1p",
			out: PackageTree{
				ImportRoot: "m1p",
				Packages: map[string]PackageOrErr{
					"m1p": {
						P: Package{
							ImportPath:  "m1p",
							CommentPath: "",
							Name:        "m1p",
							Imports: []string{
								"github.com/golang/dep/gps",
								"os",
								"sort",
							},
						},
					},
				},
			},
		},
		"one nested below": {
			fileRoot:   j("nest"),
			importRoot: "nest",
			out: PackageTree{
				ImportRoot: "nest",
				Packages: map[string]PackageOrErr{
					"nest": {
						P: Package{
							ImportPath:  "nest",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
							},
						},
					},
					"nest/m1p": {
						P: Package{
							ImportPath:  "nest/m1p",
							CommentPath: "",
							Name:        "m1p",
							Imports: []string{
								"github.com/golang/dep/gps",
								"os",
								"sort",
							},
						},
					},
				},
			},
		},
		"malformed go file": {
			fileRoot:   j("bad"),
			importRoot: "bad",
			out: PackageTree{
				ImportRoot: "bad",
				Packages: map[string]PackageOrErr{
					"bad": {
						Err: scanner.ErrorList{
							&scanner.Error{
								Pos: token.Position{
									Filename: j("bad", "bad.go"),
									Offset:   273,
									Line:     6,
									Column:   43,
								},
								Msg: "expected 'package', found 'EOF'",
							},
						},
					},
				},
			},
		},
		"two nested under empty root": {
			fileRoot:   j("ren"),
			importRoot: "ren",
			out: PackageTree{
				ImportRoot: "ren",
				Packages: map[string]PackageOrErr{
					"ren": {
						Err: &build.NoGoError{
							Dir: j("ren"),
						},
					},
					"ren/m1p": {
						P: Package{
							ImportPath:  "ren/m1p",
							CommentPath: "",
							Name:        "m1p",
							Imports: []string{
								"github.com/golang/dep/gps",
								"os",
								"sort",
							},
						},
					},
					"ren/simple": {
						P: Package{
							ImportPath:  "ren/simple",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
							},
						},
					},
				},
			},
		},
		"internal name mismatch": {
			fileRoot:   j("doublenest"),
			importRoot: "doublenest",
			out: PackageTree{
				ImportRoot: "doublenest",
				Packages: map[string]PackageOrErr{
					"doublenest": {
						P: Package{
							ImportPath:  "doublenest",
							CommentPath: "",
							Name:        "base",
							Imports: []string{
								"github.com/golang/dep/gps",
								"go/parser",
							},
						},
					},
					"doublenest/namemismatch": {
						P: Package{
							ImportPath:  "doublenest/namemismatch",
							CommentPath: "",
							Name:        "nm",
							Imports: []string{
								"github.com/Masterminds/semver",
								"os",
							},
						},
					},
					"doublenest/namemismatch/m1p": {
						P: Package{
							ImportPath:  "doublenest/namemismatch/m1p",
							CommentPath: "",
							Name:        "m1p",
							Imports: []string{
								"github.com/golang/dep/gps",
								"os",
								"sort",
							},
						},
					},
				},
			},
		},
		"file and importroot mismatch": {
			fileRoot:   j("doublenest"),
			importRoot: "other",
			out: PackageTree{
				ImportRoot: "other",
				Packages: map[string]PackageOrErr{
					"other": {
						P: Package{
							ImportPath:  "other",
							CommentPath: "",
							Name:        "base",
							Imports: []string{
								"github.com/golang/dep/gps",
								"go/parser",
							},
						},
					},
					"other/namemismatch": {
						P: Package{
							ImportPath:  "other/namemismatch",
							CommentPath: "",
							Name:        "nm",
							Imports: []string{
								"github.com/Masterminds/semver",
								"os",
							},
						},
					},
					"other/namemismatch/m1p": {
						P: Package{
							ImportPath:  "other/namemismatch/m1p",
							CommentPath: "",
							Name:        "m1p",
							Imports: []string{
								"github.com/golang/dep/gps",
								"os",
								"sort",
							},
						},
					},
				},
			},
		},
		"code and ignored main": {
			fileRoot:   j("igmain"),
			importRoot: "simple",
			out: PackageTree{
				ImportRoot: "simple",
				Packages: map[string]PackageOrErr{
					"simple": {
						P: Package{
							ImportPath:  "simple",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
								"unicode",
							},
						},
					},
				},
			},
		},
		"code and ignored main, order check": {
			fileRoot:   j("igmainfirst"),
			importRoot: "simple",
			out: PackageTree{
				ImportRoot: "simple",
				Packages: map[string]PackageOrErr{
					"simple": {
						P: Package{
							ImportPath:  "simple",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
								"unicode",
							},
						},
					},
				},
			},
		},
		"code and ignored main with comment leader": {
			fileRoot:   j("igmainlong"),
			importRoot: "simple",
			out: PackageTree{
				ImportRoot: "simple",
				Packages: map[string]PackageOrErr{
					"simple": {
						P: Package{
							ImportPath:  "simple",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
								"unicode",
							},
						},
					},
				},
			},
		},
		"code, tests, and ignored main": {
			fileRoot:   j("igmaint"),
			importRoot: "simple",
			out: PackageTree{
				ImportRoot: "simple",
				Packages: map[string]PackageOrErr{
					"simple": {
						P: Package{
							ImportPath:  "simple",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
								"unicode",
							},
							TestImports: []string{
								"math/rand",
								"strconv",
							},
						},
					},
				},
			},
		},
		// imports a missing pkg
		"missing import": {
			fileRoot:   j("missing"),
			importRoot: "missing",
			out: PackageTree{
				ImportRoot: "missing",
				Packages: map[string]PackageOrErr{
					"missing": {
						P: Package{
							ImportPath:  "missing",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"missing/missing",
								"sort",
							},
						},
					},
					"missing/m1p": {
						P: Package{
							ImportPath:  "missing/m1p",
							CommentPath: "",
							Name:        "m1p",
							Imports: []string{
								"github.com/golang/dep/gps",
								"os",
								"sort",
							},
						},
					},
				},
			},
		},
		// import cycle of three packages. ListPackages doesn't do anything
		// special with cycles - that's the reach calculator's job - so this is
		// error-free
		"import cycle, len 3": {
			fileRoot:   j("cycle"),
			importRoot: "cycle",
			out: PackageTree{
				ImportRoot: "cycle",
				Packages: map[string]PackageOrErr{
					"cycle": {
						P: Package{
							ImportPath:  "cycle",
							CommentPath: "",
							Name:        "cycle",
							Imports: []string{
								"cycle/one",
								"github.com/golang/dep/gps",
							},
						},
					},
					"cycle/one": {
						P: Package{
							ImportPath:  "cycle/one",
							CommentPath: "",
							Name:        "one",
							Imports: []string{
								"cycle/two",
								"github.com/golang/dep/gps",
							},
						},
					},
					"cycle/two": {
						P: Package{
							ImportPath:  "cycle/two",
							CommentPath: "",
							Name:        "two",
							Imports: []string{
								"cycle",
								"github.com/golang/dep/gps",
							},
						},
					},
				},
			},
		},
		// has disallowed dir names
		"disallowed dirs": {
			fileRoot:   j("disallow"),
			importRoot: "disallow",
			out: PackageTree{
				ImportRoot: "disallow",
				Packages: map[string]PackageOrErr{
					"disallow": {
						P: Package{
							ImportPath:  "disallow",
							CommentPath: "",
							Name:        "disallow",
							Imports: []string{
								"disallow/testdata",
								"github.com/golang/dep/gps",
								"sort",
							},
						},
					},
					"disallow/testdata": {
						P: Package{
							ImportPath:  "disallow/testdata",
							CommentPath: "",
							Name:        "testdata",
							Imports: []string{
								"hash",
							},
						},
					},
				},
			},
		},
		"relative imports": {
			fileRoot:   j("relimport"),
			importRoot: "relimport",
			out: PackageTree{
				ImportRoot: "relimport",
				Packages: map[string]PackageOrErr{
					"relimport": {
						P: Package{
							ImportPath:  "relimport",
							CommentPath: "",
							Name:        "relimport",
							Imports: []string{
								"sort",
							},
						},
					},
					"relimport/dot": {
						P: Package{
							ImportPath:  "relimport/dot",
							CommentPath: "",
							Name:        "dot",
							Imports: []string{
								".",
								"sort",
							},
						},
					},
					"relimport/dotdot": {
						Err: &LocalImportsError{
							Dir:        j("relimport/dotdot"),
							ImportPath: "relimport/dotdot",
							LocalImports: []string{
								"..",
							},
						},
					},
					"relimport/dotslash": {
						Err: &LocalImportsError{
							Dir:        j("relimport/dotslash"),
							ImportPath: "relimport/dotslash",
							LocalImports: []string{
								"./simple",
							},
						},
					},
					"relimport/dotdotslash": {
						Err: &LocalImportsError{
							Dir:        j("relimport/dotdotslash"),
							ImportPath: "relimport/dotdotslash",
							LocalImports: []string{
								"../github.com/golang/dep/gps",
							},
						},
					},
				},
			},
		},
		"skip underscore": {
			fileRoot:   j("skip_"),
			importRoot: "skip_",
			out: PackageTree{
				ImportRoot: "skip_",
				Packages: map[string]PackageOrErr{
					"skip_": {
						P: Package{
							ImportPath:  "skip_",
							CommentPath: "",
							Name:        "skip",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
							},
						},
					},
				},
			},
		},
		// This case mostly exists for the PackageTree methods, but it does
		// cover a bit of range
		"varied": {
			fileRoot:   j("varied"),
			importRoot: "varied",
			out: PackageTree{
				ImportRoot: "varied",
				Packages: map[string]PackageOrErr{
					"varied": {
						P: Package{
							ImportPath:  "varied",
							CommentPath: "",
							Name:        "main",
							Imports: []string{
								"net/http",
								"varied/namemismatch",
								"varied/otherpath",
								"varied/simple",
							},
						},
					},
					"varied/otherpath": {
						P: Package{
							ImportPath:  "varied/otherpath",
							CommentPath: "",
							Name:        "otherpath",
							Imports:     []string{},
							TestImports: []string{
								"varied/m1p",
							},
						},
					},
					"varied/simple": {
						P: Package{
							ImportPath:  "varied/simple",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"go/parser",
								"varied/simple/another",
							},
						},
					},
					"varied/simple/another": {
						P: Package{
							ImportPath:  "varied/simple/another",
							CommentPath: "",
							Name:        "another",
							Imports: []string{
								"hash",
								"varied/m1p",
							},
							TestImports: []string{
								"encoding/binary",
							},
						},
					},
					"varied/namemismatch": {
						P: Package{
							ImportPath:  "varied/namemismatch",
							CommentPath: "",
							Name:        "nm",
							Imports: []string{
								"github.com/Masterminds/semver",
								"os",
							},
						},
					},
					"varied/m1p": {
						P: Package{
							ImportPath:  "varied/m1p",
							CommentPath: "",
							Name:        "m1p",
							Imports: []string{
								"github.com/golang/dep/gps",
								"os",
								"sort",
							},
						},
					},
				},
			},
		},
		"varied with hidden dirs": {
			fileRoot:   j("varied_hidden"),
			importRoot: "varied",
			out: PackageTree{
				ImportRoot: "varied",
				Packages: map[string]PackageOrErr{
					"varied": {
						P: Package{
							ImportPath:  "varied",
							CommentPath: "",
							Name:        "main",
							Imports: []string{
								"net/http",
								"varied/_frommain",
								"varied/simple",
							},
						},
					},
					"varied/always": {
						P: Package{
							ImportPath:  "varied/always",
							CommentPath: "",
							Name:        "always",
							Imports:     []string{},
							TestImports: []string{
								"varied/.onlyfromtests",
							},
						},
					},
					"varied/.onlyfromtests": {
						P: Package{
							ImportPath:  "varied/.onlyfromtests",
							CommentPath: "",
							Name:        "onlyfromtests",
							Imports: []string{
								"github.com/golang/dep/gps",
								"os",
								"sort",
								"varied/_secondorder",
							},
						},
					},
					"varied/simple": {
						P: Package{
							ImportPath:  "varied/simple",
							CommentPath: "",
							Name:        "simple",
							Imports: []string{
								"github.com/golang/dep/gps",
								"go/parser",
								"varied/simple/testdata",
							},
						},
					},
					"varied/simple/testdata": {
						P: Package{
							ImportPath:  "varied/simple/testdata",
							CommentPath: "",
							Name:        "testdata",
							Imports: []string{
								"varied/dotdotslash",
							},
						},
					},
					"varied/_secondorder": {
						P: Package{
							ImportPath:  "varied/_secondorder",
							CommentPath: "",
							Name:        "secondorder",
							Imports: []string{
								"hash",
							},
						},
					},
					"varied/_never": {
						P: Package{
							ImportPath:  "varied/_never",
							CommentPath: "",
							Name:        "never",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
							},
						},
					},
					"varied/_frommain": {
						P: Package{
							ImportPath:  "varied/_frommain",
							CommentPath: "",
							Name:        "frommain",
							Imports: []string{
								"github.com/golang/dep/gps",
								"sort",
							},
						},
					},
					"varied/dotdotslash": {
						Err: &LocalImportsError{
							Dir:        j("varied_hidden/dotdotslash"),
							ImportPath: "varied/dotdotslash",
							LocalImports: []string{
								"../github.com/golang/dep/gps",
							},
						},
					},
				},
			},
		},
		"invalid buildtag like comments should be ignored": {
			fileRoot:   j("buildtag"),
			importRoot: "buildtag",
			out: PackageTree{
				ImportRoot: "buildtag",
				Packages: map[string]PackageOrErr{
					"buildtag": {
						P: Package{
							ImportPath:  "buildtag",
							CommentPath: "",
							Name:        "buildtag",
							Imports: []string{
								"sort",
							},
						},
					},
				},
			},
		},
		"does not skip directories starting with '.'": {
			fileRoot:   j("dotgodir"),
			importRoot: "dotgodir",
			out: PackageTree{
				ImportRoot: "dotgodir",
				Packages: map[string]PackageOrErr{
					"dotgodir": {
						P: Package{
							ImportPath: "dotgodir",
							Imports:    []string{},
						},
					},
					"dotgodir/.go": {
						P: Package{
							ImportPath: "dotgodir/.go",
							Name:       "dot",
							Imports:    []string{},
						},
					},
					"dotgodir/foo.go": {
						P: Package{
							ImportPath: "dotgodir/foo.go",
							Name:       "foo",
							Imports:    []string{"sort"},
						},
					},
					"dotgodir/.m1p": {
						P: Package{
							ImportPath:  "dotgodir/.m1p",
							CommentPath: "",
							Name:        "m1p",
							Imports: []string{
								"github.com/golang/dep/gps",
								"os",
								"sort",
							},
						},
					},
				},
			},
		},
		"canonical": {
			fileRoot:   j("canonical"),
			importRoot: "canonical",
			out: PackageTree{
				ImportRoot: "canonical",
				Packages: map[string]PackageOrErr{
					"canonical": {
						P: Package{
							ImportPath:  "canonical",
							CommentPath: "canonical",
							Name:        "pkg",
							Imports:     []string{},
						},
					},
					"canonical/sub": {
						P: Package{
							ImportPath:  "canonical/sub",
							CommentPath: "canonical/subpackage",
							Name:        "sub",
							Imports:     []string{},
						},
					},
				},
			},
		},
		"conflicting canonical comments": {
			fileRoot:   j("canon_confl"),
			importRoot: "canon_confl",
			out: PackageTree{
				ImportRoot: "canon_confl",
				Packages: map[string]PackageOrErr{
					"canon_confl": {
						Err: &ConflictingImportComments{
							ImportPath: "canon_confl",
							ConflictingImportComments: []string{
								"vanity1",
								"vanity2",
							},
						},
					},
				},
			},
		},
		"non-canonical": {
			fileRoot:   j("canonical"),
			importRoot: "noncanonical",
			out: PackageTree{
				ImportRoot: "noncanonical",
				Packages: map[string]PackageOrErr{
					"noncanonical": {
						Err: &NonCanonicalImportRoot{
							ImportRoot: "noncanonical",
							Canonical:  "canonical",
						},
					},
					"noncanonical/sub": {
						Err: &NonCanonicalImportRoot{
							ImportRoot: "noncanonical",
							Canonical:  "canonical/subpackage",
						},
					},
				},
			},
		},
	}

	for name, fix := range table {
		t.Run(name, func(t *testing.T) {
			if _, err := os.Stat(fix.fileRoot); err != nil {
				t.Errorf("error on fileRoot %s: %s", fix.fileRoot, err)
			}

			out, err := ListPackages(fix.fileRoot, fix.importRoot)

			if err != nil && fix.err == nil {
				t.Errorf("Received error but none expected: %s", err)
			} else if fix.err != nil && err == nil {
				t.Errorf("Error expected but none received")
			} else if fix.err != nil && err != nil {
				if !reflect.DeepEqual(fix.err, err) {
					t.Errorf("Did not receive expected error:\n\t(GOT): %s\n\t(WNT): %s", err, fix.err)
				}
			}

			if fix.out.ImportRoot != "" && fix.out.Packages != nil {
				if !reflect.DeepEqual(out, fix.out) {
					if fix.out.ImportRoot != out.ImportRoot {
						t.Errorf("Expected ImportRoot %s, got %s", fix.out.ImportRoot, out.ImportRoot)
					}

					// overwrite the out one to see if we still have a real problem
					out.ImportRoot = fix.out.ImportRoot

					if !reflect.DeepEqual(out, fix.out) {
						// TODO (kris-nova) We need to disable this bypass here, and in the .travis.yml
						// as soon as dep#501 is fixed
						bypass := os.Getenv("DEPTESTBYPASS501")
						if bypass != "" {
							t.Log("bypassing fix.out.Packages check < 2")
						} else {
							if len(fix.out.Packages) < 2 {
								t.Errorf("Did not get expected PackageOrErrs:\n\t(GOT): %#v\n\t(WNT): %#v", out, fix.out)
							} else {
								seen := make(map[string]bool)
								for path, perr := range fix.out.Packages {
									seen[path] = true
									if operr, exists := out.Packages[path]; !exists {
										t.Errorf("Expected PackageOrErr for path %s was missing from output:\n\t%s", path, perr)
									} else {
										if !reflect.DeepEqual(perr, operr) {
											t.Errorf("PkgOrErr for path %s was not as expected:\n\t(GOT): %#v\n\t(WNT): %#v", path, operr, perr)
										}
									}
								}

								for path, operr := range out.Packages {
									if seen[path] {
										continue
									}

									t.Errorf("Got PackageOrErr for path %s, but none was expected:\n\t%s", path, operr)
								}
							}
						}
					}
				}
			}
		})
	}
}

// Transform Table Test that operates solely on the varied_hidden fixture.
func TestTrimHiddenPackages(t *testing.T) {
	base, err := ListPackages(filepath.Join(getTestdataRootDir(t), "src", "varied_hidden"), "varied")
	if err != nil {
		panic(err)
	}

	table := map[string]struct {
		main, tests bool     // literal params to TrimHiddenPackages
		ignore      []string // transformed into IgnoredRuleset param to TrimHiddenPackages
		trimmed     []string // list of packages that should be trimmed in result PackageTree
	}{
		// All of these implicitly verify that the varied/_never pkg is always
		// trimmed, and that the varied/dotdotslash pkg is not trimmed even
		// though it has errors.
		"minimal trim": {
			main:  true,
			tests: true,
		},
		"ignore simple, lose testdata": {
			main:    true,
			tests:   true,
			ignore:  []string{"simple"},
			trimmed: []string{"simple", "simple/testdata"},
		},
		"no tests": {
			main:    true,
			tests:   false,
			trimmed: []string{".onlyfromtests", "_secondorder"},
		},
		"ignore a reachable hidden": {
			main:    true,
			tests:   true,
			ignore:  []string{"_secondorder"},
			trimmed: []string{"_secondorder"},
		},
		"ignore a reachable hidden with another hidden solely reachable through it": {
			main:    true,
			tests:   true,
			ignore:  []string{".onlyfromtests"},
			trimmed: []string{".onlyfromtests", "_secondorder"},
		},
		"no main": {
			main:    false,
			tests:   true,
			trimmed: []string{"", "_frommain"},
		},
		"no main or tests": {
			main:    false,
			tests:   false,
			trimmed: []string{"", "_frommain", ".onlyfromtests", "_secondorder"},
		},
		"no main or tests and ignore simple": {
			main:    false,
			tests:   false,
			ignore:  []string{"simple"},
			trimmed: []string{"", "_frommain", ".onlyfromtests", "_secondorder", "simple", "simple/testdata"},
		},
	}

	for name, fix := range table {
		t.Run(name, func(t *testing.T) {
			want := base.Copy()

			var ig []string
			for _, v := range fix.ignore {
				ig = append(ig, path.Join("varied", v))
			}
			got := base.TrimHiddenPackages(fix.main, fix.tests, NewIgnoredRuleset(ig))

			for _, ip := range append(fix.trimmed, "_never") {
				ip = path.Join("varied", ip)
				if _, has := want.Packages[ip]; !has {
					panic(fmt.Sprintf("bad input, %s does not exist in fixture ptree", ip))
				}
				delete(want.Packages, ip)
			}

			if !reflect.DeepEqual(want, got) {
				if len(want.Packages) < 2 {
					t.Errorf("Did not get expected PackageOrErrs:\n\t(GOT): %#v\n\t(WNT): %#v", got, want)
				} else {
					seen := make(map[string]bool)
					for path, perr := range want.Packages {
						seen[path] = true
						if operr, exists := got.Packages[path]; !exists {
							t.Errorf("Expected PackageOrErr for path %s was missing from output:\n\t%s", path, perr)
						} else {
							if !reflect.DeepEqual(perr, operr) {
								t.Errorf("PkgOrErr for path %s was not as expected:\n\t(GOT): %#v\n\t(WNT): %#v", path, operr, perr)
							}
						}
					}

					for path, operr := range got.Packages {
						if seen[path] {
							continue
						}

						t.Errorf("Got PackageOrErr for path %s, but none was expected:\n\t%s", path, operr)
					}
				}
			}
		})
	}
}

// Test that ListPackages skips directories for which it lacks permissions to
// enter and files it lacks permissions to read.
func TestListPackagesNoPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		// TODO This test doesn't work on windows because I wasn't able to easily
		// figure out how to chmod a dir in a way that made it untraversable.
		//
		// It's not a big deal, though, because the os.IsPermission() call we
		// use in the real code is effectively what's being tested here, and
		// that's designed to be cross-platform. So, if the unix tests pass, we
		// have every reason to believe windows tests would too, if the situation
		// arises.
		t.Skip()
	}
	tmp, err := ioutil.TempDir("", "listpkgsnp")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %s", err)
	}
	defer os.RemoveAll(tmp)

	srcdir := filepath.Join(getTestdataRootDir(t), "src", "ren")
	workdir := filepath.Join(tmp, "ren")
	fs.CopyDir(srcdir, workdir)

	// chmod the simple dir and m1p/b.go file so they can't be read
	err = os.Chmod(filepath.Join(workdir, "simple"), 0)
	if err != nil {
		t.Fatalf("Error while chmodding simple dir: %s", err)
	}
	os.Chmod(filepath.Join(workdir, "m1p", "b.go"), 0)
	if err != nil {
		t.Fatalf("Error while chmodding b.go file: %s", err)
	}

	want := PackageTree{
		ImportRoot: "ren",
		Packages: map[string]PackageOrErr{
			"ren": {
				Err: &build.NoGoError{
					Dir: workdir,
				},
			},
			"ren/m1p": {
				P: Package{
					ImportPath:  "ren/m1p",
					CommentPath: "",
					Name:        "m1p",
					Imports: []string{
						"github.com/golang/dep/gps",
						"sort",
					},
				},
			},
		},
	}

	got, err := ListPackages(workdir, "ren")

	if err != nil {
		t.Fatalf("Unexpected err from ListPackages: %s", err)
	}
	if want.ImportRoot != got.ImportRoot {
		t.Fatalf("Expected ImportRoot %s, got %s", want.ImportRoot, got.ImportRoot)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Did not get expected PackageOrErrs:\n\t(GOT): %#v\n\t(WNT): %#v", got, want)
		if len(got.Packages) != 2 {
			if len(got.Packages) == 3 {
				t.Error("Wrong number of PackageOrErrs - did 'simple' subpackage make it into results somehow?")
			} else {
				t.Error("Wrong number of PackageOrErrs")
			}
		}

		if got.Packages["ren"].Err == nil {
			t.Error("Should have gotten error on empty root directory")
		}

		if !reflect.DeepEqual(got.Packages["ren/m1p"].P.Imports, want.Packages["ren/m1p"].P.Imports) {
			t.Error("Mismatch between imports in m1p")
		}
	}
}

func TestToReachMap(t *testing.T) {
	// There's enough in the 'varied' test case to test most of what matters
	vptree, err := ListPackages(filepath.Join(getTestdataRootDir(t), "src", "github.com", "example", "varied"), "github.com/example/varied")
	if err != nil {
		t.Fatalf("ListPackages failed on varied test case: %s", err)
	}

	// Helper to add github.com/varied/example prefix
	b := func(s string) string {
		if s == "" {
			return "github.com/example/varied"
		}
		return "github.com/example/varied/" + s
	}
	bl := func(parts ...string) string {
		for k, s := range parts {
			parts[k] = b(s)
		}
		return strings.Join(parts, " ")
	}

	// Set up vars for validate closure
	var want ReachMap
	var name string
	var main, tests bool
	var ignore []string

	validate := func() {
		got, em := vptree.ToReachMap(main, tests, true, NewIgnoredRuleset(ignore))
		if len(em) != 0 {
			t.Errorf("Should not have any error packages from ToReachMap, got %s", em)
		}
		if !reflect.DeepEqual(want, got) {
			seen := make(map[string]bool)
			for ip, wantie := range want {
				seen[ip] = true
				if gotie, exists := got[ip]; !exists {
					t.Errorf("ver(%q): expected import path %s was not present in result", name, ip)
				} else {
					if !reflect.DeepEqual(wantie, gotie) {
						t.Errorf("ver(%q): did not get expected import set for pkg %s:\n\t(GOT): %#v\n\t(WNT): %#v", name, ip, gotie, wantie)
					}
				}
			}

			for ip, ie := range got {
				if seen[ip] {
					continue
				}
				t.Errorf("ver(%q): Got packages for import path %s, but none were expected:\n\t%s", name, ip, ie)
			}
		}
	}

	// maps of each internal package, and their expected external and internal
	// imports in the maximal case.
	allex := map[string][]string{
		b(""):               {"encoding/binary", "github.com/Masterminds/semver", "github.com/golang/dep/gps", "go/parser", "hash", "net/http", "os", "sort"},
		b("m1p"):            {"github.com/golang/dep/gps", "os", "sort"},
		b("namemismatch"):   {"github.com/Masterminds/semver", "os"},
		b("otherpath"):      {"github.com/golang/dep/gps", "os", "sort"},
		b("simple"):         {"encoding/binary", "github.com/golang/dep/gps", "go/parser", "hash", "os", "sort"},
		b("simple/another"): {"encoding/binary", "github.com/golang/dep/gps", "hash", "os", "sort"},
	}

	allin := map[string][]string{
		b(""):               {b("m1p"), b("namemismatch"), b("otherpath"), b("simple"), b("simple/another")},
		b("m1p"):            {},
		b("namemismatch"):   {},
		b("otherpath"):      {b("m1p")},
		b("simple"):         {b("m1p"), b("simple/another")},
		b("simple/another"): {b("m1p")},
	}

	// build a map to validate the exception inputs. do this because shit is
	// hard enough to keep track of that it's preferable not to have silent
	// success if a typo creeps in and we're trying to except an import that
	// isn't in a pkg in the first place
	valid := make(map[string]map[string]bool)
	for ip, expkgs := range allex {
		m := make(map[string]bool)
		for _, pkg := range expkgs {
			m[pkg] = true
		}
		valid[ip] = m
	}
	validin := make(map[string]map[string]bool)
	for ip, inpkgs := range allin {
		m := make(map[string]bool)
		for _, pkg := range inpkgs {
			m[pkg] = true
		}
		validin[ip] = m
	}

	// helper to compose want, excepting specific packages
	//
	// this makes it easier to see what we're taking out on each test
	except := func(pkgig ...string) {
		// reinit expect with everything from all
		want = make(ReachMap)
		for ip, expkgs := range allex {
			var ie struct{ Internal, External []string }

			inpkgs := allin[ip]
			lenex, lenin := len(expkgs), len(inpkgs)
			if lenex > 0 {
				ie.External = make([]string, len(expkgs))
				copy(ie.External, expkgs)
			}

			if lenin > 0 {
				ie.Internal = make([]string, len(inpkgs))
				copy(ie.Internal, inpkgs)
			}

			want[ip] = ie
		}

		// now build the dropmap
		drop := make(map[string]map[string]bool)
		for _, igstr := range pkgig {
			// split on space; first elem is import path to pkg, the rest are
			// the imports to drop.
			not := strings.Split(igstr, " ")
			var ip string
			ip, not = not[0], not[1:]
			if _, exists := valid[ip]; !exists {
				t.Fatalf("%s is not a package name we're working with, doofus", ip)
			}

			// if only a single elem was passed, though, drop the whole thing
			if len(not) == 0 {
				delete(want, ip)
				continue
			}

			m := make(map[string]bool)
			for _, imp := range not {
				if strings.HasPrefix(imp, "github.com/example/varied") {
					if !validin[ip][imp] {
						t.Fatalf("%s is not a reachable import of %s, even in the all case", imp, ip)
					}
				} else {
					if !valid[ip][imp] {
						t.Fatalf("%s is not a reachable import of %s, even in the all case", imp, ip)
					}
				}
				m[imp] = true
			}

			drop[ip] = m
		}

		for ip, ie := range want {
			var nie struct{ Internal, External []string }
			for _, imp := range ie.Internal {
				if !drop[ip][imp] {
					nie.Internal = append(nie.Internal, imp)
				}
			}

			for _, imp := range ie.External {
				if !drop[ip][imp] {
					nie.External = append(nie.External, imp)
				}
			}

			want[ip] = nie
		}
	}

	/* PREP IS DONE, BEGIN ACTUAL TESTING */

	// first, validate all
	name = "all"
	main, tests = true, true
	except()
	validate()

	// turn off main pkgs, which necessarily doesn't affect anything else
	name = "no main"
	main = false
	except(b(""))
	validate()

	// ignoring the "varied" pkg has same effect as disabling main pkgs
	name = "ignore root"
	ignore = []string{b("")}
	main = true
	validate()

	// when we drop tests, varied/otherpath loses its link to varied/m1p and
	// varied/simple/another loses its test import, which has a fairly big
	// cascade
	name = "no tests"
	tests = false
	ignore = nil
	except(
		b("")+" encoding/binary",
		b("simple")+" encoding/binary",
		b("simple/another")+" encoding/binary",
		b("otherpath")+" github.com/golang/dep/gps os sort",
	)

	// almost the same as previous, but varied just goes away completely
	name = "no main or tests"
	main = false
	except(
		b(""),
		b("simple")+" encoding/binary",
		b("simple/another")+" encoding/binary",
		bl("otherpath", "m1p")+" github.com/golang/dep/gps os sort",
	)
	validate()

	// focus on ignores now, so reset main and tests
	main, tests = true, true

	// now, the fun stuff. punch a hole in the middle by cutting out
	// varied/simple
	name = "ignore varied/simple"
	ignore = []string{b("simple")}
	except(
		// root pkg loses on everything in varied/simple/another
		// FIXME this is a bit odd, but should probably exclude m1p as well,
		// because it actually shouldn't be valid to import a package that only
		// has tests. This whole model misses that nuance right now, though.
		bl("", "simple", "simple/another")+" hash encoding/binary go/parser",
		b("simple"),
	)
	validate()

	// widen the hole by excluding otherpath
	name = "ignore varied/{otherpath,simple}"
	ignore = []string{
		b("otherpath"),
		b("simple"),
	}
	except(
		// root pkg loses on everything in varied/simple/another and varied/m1p
		bl("", "simple", "simple/another", "m1p", "otherpath")+" hash encoding/binary go/parser github.com/golang/dep/gps sort",
		b("otherpath"),
		b("simple"),
	)
	validate()

	// remove namemismatch, though we're mostly beating a dead horse now
	name = "ignore varied/{otherpath,simple,namemismatch}"
	ignore = append(ignore, b("namemismatch"))
	except(
		// root pkg loses on everything in varied/simple/another and varied/m1p
		bl("", "simple", "simple/another", "m1p", "otherpath", "namemismatch")+" hash encoding/binary go/parser github.com/golang/dep/gps sort os github.com/Masterminds/semver",
		b("otherpath"),
		b("simple"),
		b("namemismatch"),
	)
	validate()
}

func TestFlattenReachMap(t *testing.T) {
	// There's enough in the 'varied' test case to test most of what matters
	vptree, err := ListPackages(filepath.Join(getTestdataRootDir(t), "src", "github.com", "example", "varied"), "github.com/example/varied")
	if err != nil {
		t.Fatalf("listPackages failed on varied test case: %s", err)
	}

	all := []string{
		"encoding/binary",
		"github.com/Masterminds/semver",
		"github.com/golang/dep/gps",
		"go/parser",
		"hash",
		"net/http",
		"os",
		"sort",
	}

	// helper to generate testCase.expect as: all, except for a couple packages
	//
	// this makes it easier to see what we're taking out on each test
	except := func(not ...string) []string {
		expect := make([]string, len(all)-len(not))

		drop := make(map[string]bool)
		for _, npath := range not {
			drop[npath] = true
		}

		k := 0
		for _, path := range all {
			if !drop[path] {
				expect[k] = path
				k++
			}
		}
		return expect
	}

	for _, testCase := range []*flattenReachMapCase{
		// everything on
		{
			name:       "simple",
			expect:     except(),
			isStdLibFn: nil,
			main:       true,
			tests:      true,
		},
		// no stdlib
		{
			name:       "no stdlib",
			expect:     except("encoding/binary", "go/parser", "hash", "net/http", "os", "sort"),
			isStdLibFn: paths.IsStandardImportPath,
			main:       true,
			tests:      true,
		},
		// stdlib back in; now exclude tests, which should just cut one
		{
			name:       "no tests",
			expect:     except("encoding/binary"),
			isStdLibFn: nil,
			main:       true,
			tests:      false,
		},
		// Now skip main, which still just cuts out one
		{
			name:       "no main",
			expect:     except("net/http"),
			isStdLibFn: nil,
			main:       false,
			tests:      true,
		},
		// No test and no main, which should be additive
		{
			name:       "no tests, no main",
			expect:     except("net/http", "encoding/binary"),
			isStdLibFn: nil,
			main:       false,
			tests:      false,
		},
		// now, the ignore tests. turn main and tests back on
		// start with non-matching
		{
			name:       "non-matching ignore",
			expect:     except(),
			isStdLibFn: nil,
			main:       true,
			tests:      true,
			ignore: NewIgnoredRuleset([]string{
				"nomatch",
			}),
		},
		// should have the same effect as ignoring main
		{
			name:       "ignore the root",
			expect:     except("net/http"),
			isStdLibFn: nil,
			main:       true,
			tests:      true,
			ignore: NewIgnoredRuleset([]string{
				"github.com/example/varied",
			}),
		},
		// now drop a more interesting one
		// we get github.com/golang/dep/gps from m1p, too, so it should still be there
		{
			name:       "ignore simple",
			expect:     except("go/parser"),
			isStdLibFn: nil,
			main:       true,
			tests:      true,
			ignore: NewIgnoredRuleset([]string{
				"github.com/example/varied/simple",
			}),
		},
		// now drop two
		{
			name:       "ignore simple and nameismatch",
			expect:     except("go/parser", "github.com/Masterminds/semver"),
			isStdLibFn: nil,
			main:       true,
			tests:      true,
			ignore: NewIgnoredRuleset([]string{
				"github.com/example/varied/simple",
				"github.com/example/varied/namemismatch",
			}),
		},
		// make sure tests and main play nice with ignore
		{
			name:       "ignore simple and nameismatch, and no tests",
			expect:     except("go/parser", "github.com/Masterminds/semver", "encoding/binary"),
			isStdLibFn: nil,
			main:       true,
			tests:      false,
			ignore: NewIgnoredRuleset([]string{
				"github.com/example/varied/simple",
				"github.com/example/varied/namemismatch",
			}),
		},
		{
			name:       "ignore simple and namemismatch, and no main",
			expect:     except("go/parser", "github.com/Masterminds/semver", "net/http"),
			isStdLibFn: nil,
			main:       false,
			tests:      true,
			ignore: NewIgnoredRuleset([]string{
				"github.com/example/varied/simple",
				"github.com/example/varied/namemismatch",
			}),
		},
		{
			name:       "ignore simple and namemismatch, and no main or tests",
			expect:     except("go/parser", "github.com/Masterminds/semver", "net/http", "encoding/binary"),
			isStdLibFn: nil,
			main:       false,
			tests:      false,
			ignore: NewIgnoredRuleset([]string{
				"github.com/example/varied/simple",
				"github.com/example/varied/namemismatch",
			}),
		},
		// ignore two that should knock out gps
		{
			name:       "ignore both importers",
			expect:     except("sort", "github.com/golang/dep/gps", "go/parser"),
			isStdLibFn: nil,
			main:       true,
			tests:      true,
			ignore: NewIgnoredRuleset([]string{
				"github.com/example/varied/simple",
				"github.com/example/varied/m1p",
			}),
		},
		// finally, directly ignore some external packages
		{
			name:       "ignore external",
			expect:     except("sort", "github.com/golang/dep/gps", "go/parser"),
			isStdLibFn: nil,
			main:       true,
			tests:      true,
			ignore: NewIgnoredRuleset([]string{
				"github.com/golang/dep/gps",
				"go/parser",
				"sort",
			}),
		},
	} {
		t.Run(testCase.name, testFlattenReachMap(&vptree, testCase))
	}

	// The only thing varied *doesn't* cover is disallowed path patterns
	ptree, err := ListPackages(filepath.Join(getTestdataRootDir(t), "src", "disallow"), "disallow")
	if err != nil {
		t.Fatalf("ListPackages failed on disallow test case: %s", err)
	}

	t.Run("disallowed", testFlattenReachMap(&ptree, &flattenReachMapCase{
		name:       "disallowed",
		expect:     []string{"github.com/golang/dep/gps", "hash", "sort"},
		isStdLibFn: nil,
		main:       false,
		tests:      false,
	}))
}

type flattenReachMapCase struct {
	expect      []string
	name        string
	ignore      *IgnoredRuleset
	main, tests bool
	isStdLibFn  func(string) bool
}

func testFlattenReachMap(ptree *PackageTree, testCase *flattenReachMapCase) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		rm, em := ptree.ToReachMap(testCase.main, testCase.tests, true, testCase.ignore)
		if len(em) != 0 {
			t.Errorf("Should not have any error pkgs from ToReachMap, got %s", em)
		}
		result := rm.FlattenFn(testCase.isStdLibFn)
		if !reflect.DeepEqual(testCase.expect, result) {
			t.Errorf("Wrong imports in %q case:\n\t(GOT): %s\n\t(WNT): %s", testCase.name, result, testCase.expect)
		}
	}
}

// Verify that we handle import cycles correctly - drop em all
func TestToReachMapCycle(t *testing.T) {
	ptree, err := ListPackages(filepath.Join(getTestdataRootDir(t), "src", "cycle"), "cycle")
	if err != nil {
		t.Fatalf("ListPackages failed on cycle test case: %s", err)
	}

	rm, em := ptree.ToReachMap(true, true, false, nil)
	if len(em) != 0 {
		t.Errorf("Should not have any error packages from ToReachMap, got %s", em)
	}

	// FIXME TEMPORARILY COMMENTED UNTIL WE CREATE A BETTER LISTPACKAGES MODEL -
	//if len(rm) > 0 {
	//t.Errorf("should be empty reachmap when all packages are in a cycle, got %v", rm)
	//}

	if len(rm) == 0 {
		t.Error("TEMPORARY: should ignore import cycles, but cycle was eliminated")
	}
}

func TestToReachMapFilterDot(t *testing.T) {
	ptree, err := ListPackages(filepath.Join(getTestdataRootDir(t), "src", "relimport"), "relimport")
	if err != nil {
		t.Fatalf("ListPackages failed on relimport test case: %s", err)
	}

	rm, _ := ptree.ToReachMap(true, true, false, nil)
	if _, has := rm["relimport/dot"]; !has {
		t.Fatal("relimport/dot should not have had errors")
	}

	imports := dedupeStrings(rm["relimport/dot"].External, rm["relimport/dot"].Internal)
	for _, imp := range imports {
		if imp == "." {
			t.Fatal("dot import should have been filtered by ToReachMap")
		}
	}
}

func getTestdataRootDir(t *testing.T) string {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(cwd, "..", "_testdata")
}

// Canary regression test to make sure that if PackageTree ever gains new
// fields, we update the Copy method accordingly.
func TestCanaryPackageTreeCopy(t *testing.T) {
	ptreeFields := []string{
		"ImportRoot",
		"Packages",
	}
	packageFields := []string{
		"Name",
		"ImportPath",
		"CommentPath",
		"Imports",
		"TestImports",
	}

	fieldNames := func(typ reflect.Type) []string {
		var names []string
		for i := 0; i < typ.NumField(); i++ {
			names = append(names, typ.Field(i).Name)
		}
		return names
	}

	ptreeRefl := fieldNames(reflect.TypeOf(PackageTree{}))
	packageRefl := fieldNames(reflect.TypeOf(Package{}))

	if !reflect.DeepEqual(ptreeFields, ptreeRefl) {
		t.Errorf("PackageTree.Copy is designed to work with an exact set of fields in the PackageTree struct - make sure it (and this test) have been updated!\n\t(GOT):%s\n\t(WNT):%s", ptreeFields, ptreeRefl)
	}

	if !reflect.DeepEqual(packageFields, packageRefl) {
		t.Errorf("PackageTree.Copy is designed to work with an exact set of fields in the Package struct - make sure it (and this test) have been updated!\n\t(GOT):%s\n\t(WNT):%s", packageFields, packageRefl)
	}
}

func TestPackageTreeCopy(t *testing.T) {
	want := PackageTree{
		ImportRoot: "ren",
		Packages: map[string]PackageOrErr{
			"ren": {
				Err: &build.NoGoError{
					Dir: "some/dir",
				},
			},
			"ren/m1p": {
				P: Package{
					ImportPath:  "ren/m1p",
					CommentPath: "",
					Name:        "m1p",
					Imports: []string{
						"github.com/sdboyer/gps",
						"sort",
					},
				},
			},
		},
	}
	got := want.Copy()
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Did not get expected PackageOrErrs:\n\t(GOT): %+v\n\t(WNT): %+v", got, want)
	}
}
