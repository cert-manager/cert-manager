// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/golang/dep/gps/pkgtree"
)

var regfrom = regexp.MustCompile(`^(\w*) from (\w*) ([0-9\.\*]*)`)

// nvSplit splits an "info" string on " " into the pair of name and
// version/constraint, and returns each individually.
//
// This is for narrow use - panics if there are less than two resulting items in
// the slice.
func nvSplit(info string) (id ProjectIdentifier, version string) {
	if strings.Contains(info, " from ") {
		parts := regfrom.FindStringSubmatch(info)
		info = parts[1] + " " + parts[3]
		id.Source = parts[2]
	}

	s := strings.SplitN(info, " ", 2)
	if len(s) < 2 {
		panic(fmt.Sprintf("Malformed name/version info string '%s'", info))
	}

	id.ProjectRoot, version = ProjectRoot(s[0]), s[1]
	return
}

// nvrSplit splits an "info" string on " " into the triplet of name,
// version/constraint, and revision, and returns each individually.
//
// It will work fine if only name and version/constraint are provided.
//
// This is for narrow use - panics if there are less than two resulting items in
// the slice.
func nvrSplit(info string) (id ProjectIdentifier, version string, revision Revision) {
	if strings.Contains(info, " from ") {
		parts := regfrom.FindStringSubmatch(info)
		info = fmt.Sprintf("%s %s", parts[1], parts[3])
		id.Source = parts[2]
	}

	s := strings.SplitN(info, " ", 3)
	if len(s) < 2 {
		panic(fmt.Sprintf("Malformed name/version info string '%s'", info))
	}

	id.ProjectRoot, version = ProjectRoot(s[0]), s[1]

	if len(s) == 3 {
		revision = Revision(s[2])
	}
	return
}

// mkAtom splits the input string on a space, and uses the first two elements as
// the project identifier and version, respectively.
//
// The version segment may have a leading character indicating the type of
// version to create:
//
//  p: create a "plain" (non-semver) version.
//  b: create a branch version.
//  r: create a revision.
//
// No prefix is assumed to indicate a semver version.
//
// If a third space-delimited element is provided, it will be interepreted as a
// revision, and used as the underlying version in a PairedVersion. No prefix
// should be provided in this case. It is an error (and will panic) to try to
// pass a revision with an underlying revision.
func mkAtom(info string) atom {
	// if info is "root", special case it to use the root "version"
	if info == "root" {
		return atom{
			id: ProjectIdentifier{
				ProjectRoot: ProjectRoot("root"),
			},
			v: rootRev,
		}
	}

	id, ver, rev := nvrSplit(info)

	var v Version
	switch ver[0] {
	case 'r':
		if rev != "" {
			panic("Cannot pair a revision with a revision")
		}
		v = Revision(ver[1:])
	case 'p':
		v = NewVersion(ver[1:])
	case 'b':
		v = NewBranch(ver[1:])
	default:
		_, err := semver.NewVersion(ver)
		if err != nil {
			// don't want to allow bad test data at this level, so just panic
			panic(fmt.Sprintf("Error when converting '%s' into semver: %s", ver, err))
		}
		v = NewVersion(ver)
	}

	if rev != "" {
		v = v.(UnpairedVersion).Pair(rev)
	}

	return atom{
		id: id,
		v:  v,
	}
}

// mkPCstrnt splits the input string on a space, and uses the first two elements
// as the project identifier and constraint body, respectively.
//
// The constraint body may have a leading character indicating the type of
// version to create:
//
//  p: create a "plain" (non-semver) version.
//  b: create a branch version.
//  r: create a revision.
//
// If no leading character is used, a semver constraint is assumed.
func mkPCstrnt(info string) ProjectConstraint {
	id, ver, rev := nvrSplit(info)

	var c Constraint
	switch ver[0] {
	case 'r':
		c = Revision(ver[1:])
	case 'p':
		c = NewVersion(ver[1:])
	case 'b':
		c = NewBranch(ver[1:])
	default:
		// Without one of those leading characters, we know it's a proper semver
		// expression, so use the other parser that doesn't look for a rev
		rev = ""
		id, ver = nvSplit(info)
		var err error
		c, err = NewSemverConstraint(ver)
		if err != nil {
			// don't want bad test data at this level, so just panic
			panic(fmt.Sprintf("Error when converting '%s' into semver constraint: %s (full info: %s)", ver, err, info))
		}
	}

	// There's no practical reason that a real tool would need to produce a
	// constraint that's a PairedVersion, but it is a possibility admitted by the
	// system, so we at least allow for it in our testing harness.
	if rev != "" {
		// Of course, this *will* panic if the predicate is a revision or a
		// semver constraint, neither of which implement UnpairedVersion. This
		// is as intended, to prevent bad data from entering the system.
		c = c.(UnpairedVersion).Pair(rev)
	}

	return ProjectConstraint{
		Ident:      id,
		Constraint: c,
	}
}

// mkCDep composes a completeDep struct from the inputs.
//
// The only real work here is passing the initial string to mkPDep. All the
// other args are taken as package names.
func mkCDep(pdep string, pl ...string) completeDep {
	pc := mkPCstrnt(pdep)
	return completeDep{
		workingConstraint: workingConstraint{
			Ident:      pc.Ident,
			Constraint: pc.Constraint,
		},
		pl: pl,
	}
}

// A depspec is a fixture representing all the information a SourceManager would
// ordinarily glean directly from interrogating a repository.
type depspec struct {
	n    ProjectRoot
	v    Version
	deps []ProjectConstraint
	pkgs []tpkg
}

// mkDepspec creates a depspec by processing a series of strings, each of which
// contains an identiifer and version information.
//
// The first string is broken out into the name and version of the package being
// described - see the docs on mkAtom for details. subsequent strings are
// interpreted as dep constraints of that dep at that version. See the docs on
// mkPDep for details.
func mkDepspec(pi string, deps ...string) depspec {
	pa := mkAtom(pi)
	if string(pa.id.ProjectRoot) != pa.id.Source && pa.id.Source != "" {
		panic("alternate source on self makes no sense")
	}

	ds := depspec{
		n: pa.id.ProjectRoot,
		v: pa.v,
	}

	for _, dep := range deps {
		ds.deps = append(ds.deps, mkPCstrnt(dep))
	}

	return ds
}

func mkDep(atom, pdep string, pl ...string) dependency {
	return dependency{
		depender: mkAtom(atom),
		dep:      mkCDep(pdep, pl...),
	}
}

func mkADep(atom, pdep string, c Constraint, pl ...string) dependency {
	return dependency{
		depender: mkAtom(atom),
		dep: completeDep{
			workingConstraint: workingConstraint{
				Ident: ProjectIdentifier{
					ProjectRoot: ProjectRoot(pdep),
				},
				Constraint: c,
			},
			pl: pl,
		},
	}
}

// mkPI creates a ProjectIdentifier with the ProjectRoot as the provided
// string, and the Source unset.
//
// Call normalize() on the returned value if you need the Source to be be
// equal to the ProjectRoot.
func mkPI(root string) ProjectIdentifier {
	return ProjectIdentifier{
		ProjectRoot: ProjectRoot(root),
	}
}

// mkSVC creates a new semver constraint, panicking if an error is returned.
func mkSVC(body string) Constraint {
	c, err := NewSemverConstraint(body)
	if err != nil {
		panic(fmt.Sprintf("Error while trying to create semver constraint from %s: %s", body, err.Error()))
	}
	return c
}

// mklock makes a fixLock, suitable to act as a lock file
func mklock(pairs ...string) fixLock {
	l := make(fixLock, 0)
	for _, s := range pairs {
		pa := mkAtom(s)
		l = append(l, NewLockedProject(pa.id, pa.v, nil))
	}

	return l
}

// mkrevlock makes a fixLock, suitable to act as a lock file, with only a name
// and a rev
func mkrevlock(pairs ...string) fixLock {
	l := make(fixLock, 0)
	for _, s := range pairs {
		pa := mkAtom(s)
		l = append(l, NewLockedProject(pa.id, pa.v.(PairedVersion).Revision(), nil))
	}

	return l
}

// mksolution creates a map of project identifiers to their LockedProject
// result, which is sufficient to act as a solution fixture for the purposes of
// most tests.
//
// Either strings or LockedProjects can be provided. If a string is provided, it
// is assumed that we're in the default, "basic" case where there is exactly one
// package in a project, and it is the root of the project - meaning that only
// the "." package should be listed. If a LockedProject is provided (e.g. as
// returned from mklp()), then it's incorporated directly.
//
// If any other type is provided, the func will panic.
func mksolution(inputs ...interface{}) map[ProjectIdentifier]LockedProject {
	m := make(map[ProjectIdentifier]LockedProject)
	for _, in := range inputs {
		switch t := in.(type) {
		case string:
			a := mkAtom(t)
			m[a.id] = NewLockedProject(a.id, a.v, []string{"."})
		case LockedProject:
			m[t.Ident()] = t
		default:
			panic(fmt.Sprintf("unexpected input to mksolution: %T %s", in, in))
		}
	}

	return m
}

// mklp creates a LockedProject from string inputs
func mklp(pair string, pkgs ...string) LockedProject {
	a := mkAtom(pair)
	return NewLockedProject(a.id, a.v, pkgs)
}

// computeBasicReachMap takes a depspec and computes a reach map which is
// identical to the explicit depgraph.
//
// Using a reachMap here is overkill for what the basic fixtures actually need,
// but we use it anyway for congruence with the more general cases.
func computeBasicReachMap(ds []depspec) reachMap {
	rm := make(reachMap)

	for k, d := range ds {
		n := string(d.n)
		lm := map[string][]string{
			n: nil,
		}
		v := d.v
		if k == 0 {
			// Put the root in with a nil rev, to accommodate the solver
			v = nil
		}
		rm[pident{n: d.n, v: v}] = lm

		for _, dep := range d.deps {
			lm[n] = append(lm[n], string(dep.Ident.ProjectRoot))
		}
	}

	return rm
}

type pident struct {
	n ProjectRoot
	v Version
}

type specfix interface {
	name() string
	rootmanifest() RootManifest
	rootTree() pkgtree.PackageTree
	specs() []depspec
	maxTries() int
	solution() map[ProjectIdentifier]LockedProject
	failure() error
}

// A basicFixture is a declarative test fixture that can cover a wide variety of
// solver cases. All cases, however, maintain one invariant: package == project.
// There are no subpackages, and so it is impossible for them to trigger or
// require bimodal solving.
//
// This type is separate from bimodalFixture in part for legacy reasons - many
// of these were adapted from similar tests in dart's pub lib, where there is no
// such thing as "bimodal solving".
//
// But it's also useful to keep them separate because bimodal solving involves
// considerably more complexity than simple solving, both in terms of fixture
// declaration and actual solving mechanics. Thus, we gain a lot of value for
// contributors and maintainers by keeping comprehension costs relatively low
// while still covering important cases.
type basicFixture struct {
	// name of this fixture datum
	n string
	// depspecs. always treat first as root
	ds []depspec
	// results; map of name/atom pairs
	r map[ProjectIdentifier]LockedProject
	// max attempts the solver should need to find solution. 0 means no limit
	maxAttempts int
	// Use downgrade instead of default upgrade sorter
	downgrade bool
	// lock file simulator, if one's to be used at all
	l fixLock
	// solve failure expected, if any
	fail error
	// overrides, if any
	ovr ProjectConstraints
	// request up/downgrade to all projects
	changeall bool
	// individual projects to change
	changelist []ProjectRoot
	// if the fixture is currently broken/expected to fail, this has a message
	// recording why
	broken string
}

func (f basicFixture) name() string {
	return f.n
}

func (f basicFixture) specs() []depspec {
	return f.ds
}

func (f basicFixture) maxTries() int {
	return f.maxAttempts
}

func (f basicFixture) solution() map[ProjectIdentifier]LockedProject {
	return f.r
}

func (f basicFixture) rootmanifest() RootManifest {
	return simpleRootManifest{
		c:   pcSliceToMap(f.ds[0].deps),
		ovr: f.ovr,
	}
}

func (f basicFixture) rootTree() pkgtree.PackageTree {
	var imp []string
	for _, dep := range f.ds[0].deps {
		imp = append(imp, string(dep.Ident.ProjectRoot))
	}

	n := string(f.ds[0].n)
	pt := pkgtree.PackageTree{
		ImportRoot: n,
		Packages: map[string]pkgtree.PackageOrErr{
			string(n): {
				P: pkgtree.Package{
					ImportPath: n,
					Name:       n,
					Imports:    imp,
				},
			},
		},
	}

	return pt
}

func (f basicFixture) failure() error {
	return f.fail
}

// A table of basicFixtures, used in the basic solving test set.
var basicFixtures = map[string]basicFixture{
	// basic fixtures
	"no dependencies": {
		ds: []depspec{
			mkDepspec("root 0.0.0"),
		},
		r: mksolution(),
	},
	"simple dependency tree": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "a 1.0.0", "b 1.0.0"),
			mkDepspec("a 1.0.0", "aa 1.0.0", "ab 1.0.0"),
			mkDepspec("aa 1.0.0"),
			mkDepspec("ab 1.0.0"),
			mkDepspec("b 1.0.0", "ba 1.0.0", "bb 1.0.0"),
			mkDepspec("ba 1.0.0"),
			mkDepspec("bb 1.0.0"),
		},
		r: mksolution(
			"a 1.0.0",
			"aa 1.0.0",
			"ab 1.0.0",
			"b 1.0.0",
			"ba 1.0.0",
			"bb 1.0.0",
		),
	},
	"shared dependency with overlapping constraints": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "a 1.0.0", "b 1.0.0"),
			mkDepspec("a 1.0.0", "shared >=2.0.0, <4.0.0"),
			mkDepspec("b 1.0.0", "shared >=3.0.0, <5.0.0"),
			mkDepspec("shared 2.0.0"),
			mkDepspec("shared 3.0.0"),
			mkDepspec("shared 3.6.9"),
			mkDepspec("shared 4.0.0"),
			mkDepspec("shared 5.0.0"),
		},
		r: mksolution(
			"a 1.0.0",
			"b 1.0.0",
			"shared 3.6.9",
		),
	},
	"downgrade on overlapping constraints": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "a 1.0.0", "b 1.0.0"),
			mkDepspec("a 1.0.0", "shared >=2.0.0, <=4.0.0"),
			mkDepspec("b 1.0.0", "shared >=3.0.0, <5.0.0"),
			mkDepspec("shared 2.0.0"),
			mkDepspec("shared 3.0.0"),
			mkDepspec("shared 3.6.9"),
			mkDepspec("shared 4.0.0"),
			mkDepspec("shared 5.0.0"),
		},
		r: mksolution(
			"a 1.0.0",
			"b 1.0.0",
			"shared 3.0.0",
		),
		downgrade: true,
	},
	"shared dependency where dependent version in turn affects other dependencies": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo <=1.0.2", "bar 1.0.0"),
			mkDepspec("foo 1.0.0"),
			mkDepspec("foo 1.0.1", "bang 1.0.0"),
			mkDepspec("foo 1.0.2", "whoop 1.0.0"),
			mkDepspec("foo 1.0.3", "zoop 1.0.0"),
			mkDepspec("bar 1.0.0", "foo <=1.0.1"),
			mkDepspec("bang 1.0.0"),
			mkDepspec("whoop 1.0.0"),
			mkDepspec("zoop 1.0.0"),
		},
		r: mksolution(
			"foo 1.0.1",
			"bar 1.0.0",
			"bang 1.0.0",
		),
	},
	"removed dependency": {
		ds: []depspec{
			mkDepspec("root 1.0.0", "foo 1.0.0", "bar *"),
			mkDepspec("foo 1.0.0"),
			mkDepspec("foo 2.0.0"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 2.0.0", "baz 1.0.0"),
			mkDepspec("baz 1.0.0", "foo 2.0.0"),
		},
		r: mksolution(
			"foo 1.0.0",
			"bar 1.0.0",
		),
		maxAttempts: 2,
	},
	// fixtures with locks
	"with compatible locked dependency": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *"),
			mkDepspec("foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 1.0.1", "bar 1.0.1"),
			mkDepspec("foo 1.0.2", "bar 1.0.2"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 1.0.1"),
			mkDepspec("bar 1.0.2"),
		},
		l: mklock(
			"foo 1.0.1",
		),
		r: mksolution(
			"foo 1.0.1",
			"bar 1.0.1",
		),
	},
	"upgrade through lock": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *"),
			mkDepspec("foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 1.0.1", "bar 1.0.1"),
			mkDepspec("foo 1.0.2", "bar 1.0.2"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 1.0.1"),
			mkDepspec("bar 1.0.2"),
		},
		l: mklock(
			"foo 1.0.1",
		),
		r: mksolution(
			"foo 1.0.2",
			"bar 1.0.2",
		),
		changeall: true,
	},
	"downgrade through lock": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *"),
			mkDepspec("foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 1.0.1", "bar 1.0.1"),
			mkDepspec("foo 1.0.2", "bar 1.0.2"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 1.0.1"),
			mkDepspec("bar 1.0.2"),
		},
		l: mklock(
			"foo 1.0.1",
		),
		r: mksolution(
			"foo 1.0.0",
			"bar 1.0.0",
		),
		changeall: true,
		downgrade: true,
	},
	"update one with only one": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *"),
			mkDepspec("foo 1.0.0"),
			mkDepspec("foo 1.0.1"),
			mkDepspec("foo 1.0.2"),
		},
		l: mklock(
			"foo 1.0.1",
		),
		r: mksolution(
			"foo 1.0.2",
		),
		changelist: []ProjectRoot{"foo"},
	},
	"update one of multi": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *", "bar *"),
			mkDepspec("foo 1.0.0"),
			mkDepspec("foo 1.0.1"),
			mkDepspec("foo 1.0.2"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 1.0.1"),
			mkDepspec("bar 1.0.2"),
		},
		l: mklock(
			"foo 1.0.1",
			"bar 1.0.1",
		),
		r: mksolution(
			"foo 1.0.2",
			"bar 1.0.1",
		),
		changelist: []ProjectRoot{"foo"},
	},
	"update both of multi": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *", "bar *"),
			mkDepspec("foo 1.0.0"),
			mkDepspec("foo 1.0.1"),
			mkDepspec("foo 1.0.2"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 1.0.1"),
			mkDepspec("bar 1.0.2"),
		},
		l: mklock(
			"foo 1.0.1",
			"bar 1.0.1",
		),
		r: mksolution(
			"foo 1.0.2",
			"bar 1.0.2",
		),
		changelist: []ProjectRoot{"foo", "bar"},
	},
	"update two of more": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *", "bar *", "baz *"),
			mkDepspec("foo 1.0.0"),
			mkDepspec("foo 1.0.1"),
			mkDepspec("foo 1.0.2"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 1.0.1"),
			mkDepspec("bar 1.0.2"),
			mkDepspec("baz 1.0.0"),
			mkDepspec("baz 1.0.1"),
			mkDepspec("baz 1.0.2"),
		},
		l: mklock(
			"foo 1.0.1",
			"bar 1.0.1",
			"baz 1.0.1",
		),
		r: mksolution(
			"foo 1.0.2",
			"bar 1.0.2",
			"baz 1.0.1",
		),
		changelist: []ProjectRoot{"foo", "bar"},
	},
	"break other lock with targeted update": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *", "baz *"),
			mkDepspec("foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 1.0.1", "bar 1.0.1"),
			mkDepspec("foo 1.0.2", "bar 1.0.2"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 1.0.1"),
			mkDepspec("bar 1.0.2"),
			mkDepspec("baz 1.0.0"),
			mkDepspec("baz 1.0.1"),
			mkDepspec("baz 1.0.2"),
		},
		l: mklock(
			"foo 1.0.1",
			"bar 1.0.1",
			"baz 1.0.1",
		),
		r: mksolution(
			"foo 1.0.2",
			"bar 1.0.2",
			"baz 1.0.1",
		),
		changelist: []ProjectRoot{"foo", "bar"},
	},
	"with incompatible locked dependency": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo >1.0.1"),
			mkDepspec("foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 1.0.1", "bar 1.0.1"),
			mkDepspec("foo 1.0.2", "bar 1.0.2"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 1.0.1"),
			mkDepspec("bar 1.0.2"),
		},
		l: mklock(
			"foo 1.0.1",
		),
		r: mksolution(
			"foo 1.0.2",
			"bar 1.0.2",
		),
	},
	"with unrelated locked dependency": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *"),
			mkDepspec("foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 1.0.1", "bar 1.0.1"),
			mkDepspec("foo 1.0.2", "bar 1.0.2"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 1.0.1"),
			mkDepspec("bar 1.0.2"),
			mkDepspec("baz 1.0.0 bazrev"),
		},
		l: mklock(
			"baz 1.0.0 bazrev",
		),
		r: mksolution(
			"foo 1.0.2",
			"bar 1.0.2",
		),
	},
	"unlocks dependencies if necessary to ensure that a new dependency is satisfied": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *", "newdep *"),
			mkDepspec("foo 1.0.0 foorev", "bar <2.0.0"),
			mkDepspec("bar 1.0.0 barrev", "baz <2.0.0"),
			mkDepspec("baz 1.0.0 bazrev", "qux <2.0.0"),
			mkDepspec("qux 1.0.0 quxrev"),
			mkDepspec("foo 2.0.0", "bar <3.0.0"),
			mkDepspec("bar 2.0.0", "baz <3.0.0"),
			mkDepspec("baz 2.0.0", "qux <3.0.0"),
			mkDepspec("qux 2.0.0"),
			mkDepspec("newdep 2.0.0", "baz >=1.5.0"),
		},
		l: mklock(
			"foo 1.0.0 foorev",
			"bar 1.0.0 barrev",
			"baz 1.0.0 bazrev",
			"qux 1.0.0 quxrev",
		),
		r: mksolution(
			"foo 2.0.0",
			"bar 2.0.0",
			"baz 2.0.0",
			"qux 1.0.0 quxrev",
			"newdep 2.0.0",
		),
		maxAttempts: 4,
	},
	"break lock when only the deps necessitate it": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *", "bar *"),
			mkDepspec("foo 1.0.0 foorev", "bar <2.0.0"),
			mkDepspec("foo 2.0.0", "bar <3.0.0"),
			mkDepspec("bar 2.0.0", "baz <3.0.0"),
			mkDepspec("baz 2.0.0", "foo >1.0.0"),
		},
		l: mklock(
			"foo 1.0.0 foorev",
		),
		r: mksolution(
			"foo 2.0.0",
			"bar 2.0.0",
			"baz 2.0.0",
		),
		maxAttempts: 4,
	},
	"locked atoms are matched on both local and net name": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *"),
			mkDepspec("foo 1.0.0 foorev"),
			mkDepspec("foo 2.0.0 foorev2"),
		},
		l: mklock(
			"foo from baz 1.0.0 foorev",
		),
		r: mksolution(
			"foo 2.0.0 foorev2",
		),
	},
	// This fixture describes a situation that should be impossible with a
	// real-world VCS (contents of dep at same rev are different, as indicated
	// by different constraints on bar). But, that's not the SUT here, so it's
	// OK.
	"pairs bare revs in lock with all versions": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo ~1.0.1"),
			mkDepspec("foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 1.0.1 foorev", "bar 1.0.1"),
			mkDepspec("foo 1.0.2 foorev", "bar 1.0.2"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 1.0.1"),
			mkDepspec("bar 1.0.2"),
		},
		l: mkrevlock(
			"foo 1.0.1 foorev", // mkrevlock drops the 1.0.1
		),
		r: mksolution(
			"foo 1.0.2 foorev",
			"bar 1.0.2",
		),
	},
	"does not pair bare revs in manifest with unpaired lock version": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo ~1.0.1"),
			mkDepspec("foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 1.0.1 foorev", "bar 1.0.1"),
			mkDepspec("foo 1.0.2", "bar 1.0.2"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 1.0.1"),
			mkDepspec("bar 1.0.2"),
		},
		l: mkrevlock(
			"foo 1.0.1 foorev", // mkrevlock drops the 1.0.1
		),
		r: mksolution(
			"foo 1.0.2",
			"bar 1.0.2",
		),
	},
	"lock to branch on old rev keeps old rev": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo bmaster"),
			mkDepspec("foo bmaster newrev"),
		},
		l: mklock(
			"foo bmaster oldrev",
		),
		r: mksolution(
			"foo bmaster oldrev",
		),
	},
	// Whereas this is a normal situation for a branch, when it occurs for a
	// tag, it means someone's been naughty upstream. Still, though, the outcome
	// is the same.
	//
	// TODO(sdboyer) this needs to generate a warning, once we start doing that
	"lock to now-moved tag on old rev keeps old rev": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo ptaggerino"),
			mkDepspec("foo ptaggerino newrev"),
		},
		l: mklock(
			"foo ptaggerino oldrev",
		),
		r: mksolution(
			"foo ptaggerino oldrev",
		),
	},
	"no version that matches requirement": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo ^1.0.0"),
			mkDepspec("foo 2.0.0"),
			mkDepspec("foo 2.1.3"),
		},
		fail: &noVersionError{
			pn: mkPI("foo"),
			fails: []failedVersion{
				{
					v: NewVersion("2.1.3"),
					f: &versionNotAllowedFailure{
						goal:       mkAtom("foo 2.1.3"),
						failparent: []dependency{mkDep("root", "foo ^1.0.0", "foo")},
						c:          mkSVC("^1.0.0"),
					},
				},
				{
					v: NewVersion("2.0.0"),
					f: &versionNotAllowedFailure{
						goal:       mkAtom("foo 2.0.0"),
						failparent: []dependency{mkDep("root", "foo ^1.0.0", "foo")},
						c:          mkSVC("^1.0.0"),
					},
				},
			},
		},
	},
	"no version that matches combined constraint": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 1.0.0", "shared >=2.0.0, <3.0.0"),
			mkDepspec("bar 1.0.0", "shared >=2.9.0, <4.0.0"),
			mkDepspec("shared 2.5.0"),
			mkDepspec("shared 3.5.0"),
		},
		fail: &noVersionError{
			pn: mkPI("shared"),
			fails: []failedVersion{
				{
					v: NewVersion("3.5.0"),
					f: &versionNotAllowedFailure{
						goal:       mkAtom("shared 3.5.0"),
						failparent: []dependency{mkDep("foo 1.0.0", "shared >=2.0.0, <3.0.0", "shared")},
						c:          mkSVC(">=2.9.0, <3.0.0"),
					},
				},
				{
					v: NewVersion("2.5.0"),
					f: &versionNotAllowedFailure{
						goal:       mkAtom("shared 2.5.0"),
						failparent: []dependency{mkDep("bar 1.0.0", "shared >=2.9.0, <4.0.0", "shared")},
						c:          mkSVC(">=2.9.0, <3.0.0"),
					},
				},
			},
		},
	},
	"disjoint constraints": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 1.0.0", "shared <=2.0.0"),
			mkDepspec("bar 1.0.0", "shared >3.0.0"),
			mkDepspec("shared 2.0.0"),
			mkDepspec("shared 4.0.0"),
		},
		fail: &noVersionError{
			pn: mkPI("foo"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &disjointConstraintFailure{
						goal:      mkDep("foo 1.0.0", "shared <=2.0.0", "shared"),
						failsib:   []dependency{mkDep("bar 1.0.0", "shared >3.0.0", "shared")},
						nofailsib: nil,
						c:         mkSVC(">3.0.0"),
					},
				},
			},
		},
	},
	"no valid solution": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "a *", "b *"),
			mkDepspec("a 1.0.0", "b 1.0.0"),
			mkDepspec("a 2.0.0", "b 2.0.0"),
			mkDepspec("b 1.0.0", "a 2.0.0"),
			mkDepspec("b 2.0.0", "a 1.0.0"),
		},
		fail: &noVersionError{
			pn: mkPI("b"),
			fails: []failedVersion{
				{
					v: NewVersion("2.0.0"),
					f: &versionNotAllowedFailure{
						goal:       mkAtom("b 2.0.0"),
						failparent: []dependency{mkDep("a 1.0.0", "b 1.0.0", "b")},
						c:          mkSVC("1.0.0"),
					},
				},
				{
					v: NewVersion("1.0.0"),
					f: &constraintNotAllowedFailure{
						goal: mkDep("b 1.0.0", "a 2.0.0", "a"),
						v:    NewVersion("1.0.0"),
					},
				},
			},
		},
	},
	"no version that matches while backtracking": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "a *", "b >1.0.0"),
			mkDepspec("a 1.0.0"),
			mkDepspec("b 1.0.0"),
		},
		fail: &noVersionError{
			pn: mkPI("b"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &versionNotAllowedFailure{
						goal:       mkAtom("b 1.0.0"),
						failparent: []dependency{mkDep("root", "b >1.0.0", "b")},
						c:          mkSVC(">1.0.0"),
					},
				},
			},
		},
	},
	// The latest versions of a and b disagree on c. An older version of either
	// will resolve the problem. This test validates that b, which is farther
	// in the dependency graph from myapp is downgraded first.
	"rolls back leaf versions first": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "a *"),
			mkDepspec("a 1.0.0", "b *"),
			mkDepspec("a 2.0.0", "b *", "c 2.0.0"),
			mkDepspec("b 1.0.0"),
			mkDepspec("b 2.0.0", "c 1.0.0"),
			mkDepspec("c 1.0.0"),
			mkDepspec("c 2.0.0"),
		},
		r: mksolution(
			"a 2.0.0",
			"b 1.0.0",
			"c 2.0.0",
		),
		maxAttempts: 2,
	},
	// Only one version of baz, so foo and bar will have to downgrade until they
	// reach it.
	"mutual downgrading": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *"),
			mkDepspec("foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 2.0.0", "bar 2.0.0"),
			mkDepspec("foo 3.0.0", "bar 3.0.0"),
			mkDepspec("bar 1.0.0", "baz *"),
			mkDepspec("bar 2.0.0", "baz 2.0.0"),
			mkDepspec("bar 3.0.0", "baz 3.0.0"),
			mkDepspec("baz 1.0.0"),
		},
		r: mksolution(
			"foo 1.0.0",
			"bar 1.0.0",
			"baz 1.0.0",
		),
		maxAttempts: 3,
	},
	// Ensures the solver doesn't exhaustively search all versions of b when
	// it's a-2.0.0 whose dependency on c-2.0.0-nonexistent led to the
	// problem. We make sure b has more versions than a so that the solver
	// tries a first since it sorts sibling dependencies by number of
	// versions.
	"search real failer": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "a *", "b *"),
			mkDepspec("a 1.0.0", "c 1.0.0"),
			mkDepspec("a 2.0.0", "c 2.0.0"),
			mkDepspec("b 1.0.0"),
			mkDepspec("b 2.0.0"),
			mkDepspec("b 3.0.0"),
			mkDepspec("c 1.0.0"),
		},
		r: mksolution(
			"a 1.0.0",
			"b 3.0.0",
			"c 1.0.0",
		),
		maxAttempts: 2,
	},
	// Dependencies are ordered so that packages with fewer versions are tried
	// first. Here, there are two valid solutions (either a or b must be
	// downgraded once). The chosen one depends on which dep is traversed first.
	// Since b has fewer versions, it will be traversed first, which means a
	// will come later. Since later selections are revised first, a gets
	// downgraded.
	"traverse into package with fewer versions first": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "a *", "b *"),
			mkDepspec("a 1.0.0", "c *"),
			mkDepspec("a 2.0.0", "c *"),
			mkDepspec("a 3.0.0", "c *"),
			mkDepspec("a 4.0.0", "c *"),
			mkDepspec("a 5.0.0", "c 1.0.0"),
			mkDepspec("b 1.0.0", "c *"),
			mkDepspec("b 2.0.0", "c *"),
			mkDepspec("b 3.0.0", "c *"),
			mkDepspec("b 4.0.0", "c 2.0.0"),
			mkDepspec("c 1.0.0"),
			mkDepspec("c 2.0.0"),
		},
		r: mksolution(
			"a 4.0.0",
			"b 4.0.0",
			"c 2.0.0",
		),
		maxAttempts: 2,
	},
	// This is similar to the preceding fixture. When getting the number of
	// versions of a package to determine which to traverse first, versions that
	// are disallowed by the root package's constraints should not be
	// considered. Here, foo has more versions than bar in total (4), but fewer
	// that meet myapp"s constraints (only 2). There is no solution, but we will
	// do less backtracking if foo is tested first.
	"root constraints pre-eliminate versions": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *", "bar *"),
			mkDepspec("foo 1.0.0", "none 2.0.0"),
			mkDepspec("foo 2.0.0", "none 2.0.0"),
			mkDepspec("foo 3.0.0", "none 2.0.0"),
			mkDepspec("foo 4.0.0", "none 2.0.0"),
			mkDepspec("bar 1.0.0"),
			mkDepspec("bar 2.0.0"),
			mkDepspec("bar 3.0.0"),
			mkDepspec("none 1.0.0"),
		},
		fail: &noVersionError{
			pn: mkPI("none"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &versionNotAllowedFailure{
						goal:       mkAtom("none 1.0.0"),
						failparent: []dependency{mkDep("foo 1.0.0", "none 2.0.0", "none")},
						c:          mkSVC("2.0.0"),
					},
				},
			},
		},
	},
	// If there"s a disjoint constraint on a package, then selecting other
	// versions of it is a waste of time: no possible versions can match. We
	// need to jump past it to the most recent package that affected the
	// constraint.
	"backjump past failed package on disjoint constraint": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "a *", "foo *"),
			mkDepspec("a 1.0.0", "foo *"),
			mkDepspec("a 2.0.0", "foo <1.0.0"),
			mkDepspec("foo 2.0.0"),
			mkDepspec("foo 2.0.1"),
			mkDepspec("foo 2.0.2"),
			mkDepspec("foo 2.0.3"),
			mkDepspec("foo 2.0.4"),
			mkDepspec("none 1.0.0"),
		},
		r: mksolution(
			"a 1.0.0",
			"foo 2.0.4",
		),
		maxAttempts: 2,
	},
	// Revision enters vqueue if a dep has a constraint on that revision
	"revision injected into vqueue": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo r123abc"),
			mkDepspec("foo r123abc"),
			mkDepspec("foo 1.0.0 foorev"),
			mkDepspec("foo 2.0.0 foorev2"),
		},
		r: mksolution(
			"foo r123abc",
		),
	},
	// Some basic override checks
	"override root's own constraint": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "a *", "b *"),
			mkDepspec("a 1.0.0", "b 1.0.0"),
			mkDepspec("a 2.0.0", "b 1.0.0"),
			mkDepspec("b 1.0.0"),
		},
		ovr: ProjectConstraints{
			ProjectRoot("a"): ProjectProperties{
				Constraint: NewVersion("1.0.0"),
			},
		},
		r: mksolution(
			"a 1.0.0",
			"b 1.0.0",
		),
	},
	"override dep's constraint": {
		ds: []depspec{
			mkDepspec("root 0.0.0", "a *"),
			mkDepspec("a 1.0.0", "b 1.0.0"),
			mkDepspec("a 2.0.0", "b 1.0.0"),
			mkDepspec("b 1.0.0"),
			mkDepspec("b 2.0.0"),
		},
		ovr: ProjectConstraints{
			ProjectRoot("b"): ProjectProperties{
				Constraint: NewVersion("2.0.0"),
			},
		},
		r: mksolution(
			"a 2.0.0",
			"b 2.0.0",
		),
	},
	"overridden mismatched net addrs, alt in dep, back to default": {
		ds: []depspec{
			mkDepspec("root 1.0.0", "foo 1.0.0", "bar 1.0.0"),
			mkDepspec("foo 1.0.0", "bar from baz 1.0.0"),
			mkDepspec("bar 1.0.0"),
		},
		ovr: ProjectConstraints{
			ProjectRoot("bar"): ProjectProperties{
				Source: "bar",
			},
		},
		r: mksolution(
			"foo 1.0.0",
			"bar from bar 1.0.0",
		),
	},

	// TODO(sdboyer) decide how to refactor the solver in order to re-enable these.
	// Checking for revision existence is important...but kinda obnoxious.
	//{
	//// Solve fails if revision constraint calls for a nonexistent revision
	//n: "fail on missing revision",
	//ds: []depspec{
	//mkDepspec("root 0.0.0", "bar *"),
	//mkDepspec("bar 1.0.0", "foo r123abc"),
	//mkDepspec("foo r123nomatch"),
	//mkDepspec("foo 1.0.0"),
	//mkDepspec("foo 2.0.0"),
	//},
	//errp: []string{"bar", "foo", "bar"},
	//},
	//{
	//// Solve fails if revision constraint calls for a nonexistent revision,
	//// even if rev constraint is specified by root
	//n: "fail on missing revision from root",
	//ds: []depspec{
	//mkDepspec("root 0.0.0", "foo r123nomatch"),
	//mkDepspec("foo r123abc"),
	//mkDepspec("foo 1.0.0"),
	//mkDepspec("foo 2.0.0"),
	//},
	//errp: []string{"foo", "root", "foo"},
	//},

	// TODO(sdboyer) add fixture that tests proper handling of loops via aliases (where
	// a project that wouldn't be a loop is aliased to a project that is a loop)
}

func init() {
	// This sets up a hundred versions of foo and bar, 0.0.0 through 9.9.0. Each
	// version of foo depends on a baz with the same major version. Each version
	// of bar depends on a baz with the same minor version. There is only one
	// version of baz, 0.0.0, so only older versions of foo and bar will
	// satisfy it.
	fix := basicFixture{
		ds: []depspec{
			mkDepspec("root 0.0.0", "foo *", "bar *"),
			mkDepspec("baz 0.0.0"),
		},
		r: mksolution(
			"foo 0.9.0",
			"bar 9.0.0",
			"baz 0.0.0",
		),
		maxAttempts: 10,
	}

	for i := 0; i < 10; i++ {
		for j := 0; j < 10; j++ {
			fix.ds = append(fix.ds, mkDepspec(fmt.Sprintf("foo %v.%v.0", i, j), fmt.Sprintf("baz %v.0.0", i)))
			fix.ds = append(fix.ds, mkDepspec(fmt.Sprintf("bar %v.%v.0", i, j), fmt.Sprintf("baz 0.%v.0", j)))
		}
	}

	basicFixtures["complex backtrack"] = fix

	for k, fix := range basicFixtures {
		// Assign the name into the fixture itself
		fix.n = k
		basicFixtures[k] = fix
	}
}

// reachMaps contain externalReach()-type data for a given depspec fixture's
// universe of projects, packages, and versions.
type reachMap map[pident]map[string][]string

type depspecSourceManager struct {
	specs []depspec
	rm    reachMap
	ig    map[string]bool
}

type fixSM interface {
	SourceManager
	rootSpec() depspec
	allSpecs() []depspec
	ignore() map[string]bool
}

var _ fixSM = &depspecSourceManager{}

func newdepspecSM(ds []depspec, ignore []string) *depspecSourceManager {
	ig := make(map[string]bool)
	if len(ignore) > 0 {
		for _, pkg := range ignore {
			ig[pkg] = true
		}
	}

	return &depspecSourceManager{
		specs: ds,
		rm:    computeBasicReachMap(ds),
		ig:    ig,
	}
}

func (sm *depspecSourceManager) GetManifestAndLock(id ProjectIdentifier, v Version, an ProjectAnalyzer) (Manifest, Lock, error) {
	// If the input version is a PairedVersion, look only at its top version,
	// not the underlying. This is generally consistent with the idea that, for
	// this class of lookup, the rev probably DOES exist, but upstream changed
	// it (typically a branch). For the purposes of tests, then, that's an OK
	// scenario, because otherwise we'd have to enumerate all the revs in the
	// fixture declarations, which would screw up other things.
	if pv, ok := v.(PairedVersion); ok {
		v = pv.Unpair()
	}

	src := toFold(id.normalizedSource())
	for _, ds := range sm.specs {
		if src == string(ds.n) && v.Matches(ds.v) {
			return ds, dummyLock{}, nil
		}
	}

	return nil, nil, fmt.Errorf("project %s at version %s could not be found", id, v)
}

func (sm *depspecSourceManager) ListPackages(id ProjectIdentifier, v Version) (pkgtree.PackageTree, error) {
	pid := pident{n: ProjectRoot(toFold(id.normalizedSource())), v: v}
	if pv, ok := v.(PairedVersion); ok && pv.Revision() == "FAKEREV" {
		// An empty rev may come in here because that's what we produce in
		// ListVersions(). If that's what we see, then just pretend like we have
		// an unpaired.
		pid.v = pv.Unpair()
	}

	if r, exists := sm.rm[pid]; exists {
		return pkgtree.PackageTree{
			ImportRoot: id.normalizedSource(),
			Packages: map[string]pkgtree.PackageOrErr{
				string(pid.n): {
					P: pkgtree.Package{
						ImportPath: string(pid.n),
						Name:       string(pid.n),
						Imports:    r[string(pid.n)],
					},
				},
			},
		}, nil
	}

	// if incoming version was paired, walk the map and search for a match on
	// top-only version
	if pv, ok := v.(PairedVersion); ok {
		uv := pv.Unpair()
		for pid, r := range sm.rm {
			if uv.Matches(pid.v) {
				return pkgtree.PackageTree{
					ImportRoot: id.normalizedSource(),
					Packages: map[string]pkgtree.PackageOrErr{
						string(pid.n): {
							P: pkgtree.Package{
								ImportPath: string(pid.n),
								Name:       string(pid.n),
								Imports:    r[string(pid.n)],
							},
						},
					},
				}, nil
			}
		}
	}

	return pkgtree.PackageTree{}, fmt.Errorf("project %s at version %s could not be found", pid.n, v)
}

func (sm *depspecSourceManager) ListVersions(id ProjectIdentifier) ([]PairedVersion, error) {
	var pvl []PairedVersion
	src := toFold(id.normalizedSource())
	for _, ds := range sm.specs {
		if src != string(ds.n) {
			continue
		}

		switch tv := ds.v.(type) {
		case Revision:
			// To simulate the behavior of the real SourceManager, we do not return
			// raw revisions from listVersions().
		case PairedVersion:
			pvl = append(pvl, tv)
		case UnpairedVersion:
			// Dummy revision; if the fixture doesn't provide it, we know
			// the test doesn't need revision info, anyway.
			pvl = append(pvl, tv.Pair(Revision("FAKEREV")))
		default:
			panic(fmt.Sprintf("unreachable: type of version was %#v for spec %s", ds.v, id))
		}
	}

	if len(pvl) == 0 {
		return nil, fmt.Errorf("project %s could not be found", id)
	}
	return pvl, nil
}

func (sm *depspecSourceManager) RevisionPresentIn(id ProjectIdentifier, r Revision) (bool, error) {
	src := toFold(id.normalizedSource())
	for _, ds := range sm.specs {
		if src == string(ds.n) && r == ds.v {
			return true, nil
		}
	}

	return false, fmt.Errorf("project %s has no revision %s", id, r)
}

func (sm *depspecSourceManager) SourceExists(id ProjectIdentifier) (bool, error) {
	src := toFold(id.normalizedSource())
	for _, ds := range sm.specs {
		if src == string(ds.n) {
			return true, nil
		}
	}

	return false, nil
}

func (sm *depspecSourceManager) SyncSourceFor(id ProjectIdentifier) error {
	// Ignore err because it can't happen
	if exist, _ := sm.SourceExists(id); !exist {
		return fmt.Errorf("source %s does not exist", id)
	}
	return nil
}

func (sm *depspecSourceManager) Release() {}

func (sm *depspecSourceManager) ExportProject(context.Context, ProjectIdentifier, Version, string) error {
	return fmt.Errorf("dummy sm doesn't support exporting")
}

func (sm *depspecSourceManager) ExportPrunedProject(context.Context, LockedProject, PruneOptions, string) error {
	return fmt.Errorf("dummy sm doesn't support exporting")
}

func (sm *depspecSourceManager) DeduceProjectRoot(ip string) (ProjectRoot, error) {
	fip := toFold(ip)
	for _, ds := range sm.allSpecs() {
		n := string(ds.n)
		if fip == n || strings.HasPrefix(fip, n+"/") {
			return ProjectRoot(ip[:len(n)]), nil
		}
	}
	return "", fmt.Errorf("could not find %s, or any parent, in list of known fixtures", ip)
}

func (sm *depspecSourceManager) SourceURLsForPath(ip string) ([]*url.URL, error) {
	return nil, fmt.Errorf("dummy sm doesn't implement SourceURLsForPath")
}

func (sm *depspecSourceManager) rootSpec() depspec {
	return sm.specs[0]
}

func (sm *depspecSourceManager) allSpecs() []depspec {
	return sm.specs
}

func (sm *depspecSourceManager) ignore() map[string]bool {
	return sm.ig
}

// InferConstraint tries to puzzle out what kind of version is given in a string -
// semver, a revision, or as a fallback, a plain tag. This current implementation
// is a panic because there's no current circumstance under which the depspecSourceManager
// is useful outside of the gps solving tests, and it shouldn't be used anywhere else without a conscious and intentional
// expansion of its semantics.
func (sm *depspecSourceManager) InferConstraint(s string, pi ProjectIdentifier) (Constraint, error) {
	panic("depsecSourceManager is only for gps solving tests")
}

type depspecBridge struct {
	*bridge
}

func (b *depspecBridge) listVersions(id ProjectIdentifier) ([]Version, error) {
	if vl, exists := b.vlists[id]; exists {
		return vl, nil
	}

	pvl, err := b.sm.ListVersions(id)
	if err != nil {
		return nil, err
	}

	// Construct a []Version slice. If any paired versions use the fake rev,
	// remove the underlying component.
	vl := make([]Version, 0, len(pvl))
	for _, v := range pvl {
		if v.Revision() == "FAKEREV" {
			vl = append(vl, v.Unpair())
		} else {
			vl = append(vl, v)
		}
	}

	if b.down {
		SortForDowngrade(vl)
	} else {
		SortForUpgrade(vl)
	}

	b.vlists[id] = vl
	return vl, nil
}

// override verifyRoot() on bridge to prevent any filesystem interaction
func (b *depspecBridge) verifyRootDir(path string) error {
	root := b.sm.(fixSM).rootSpec()
	if string(root.n) != path {
		return fmt.Errorf("expected only root project %q to verifyRootDir(), got %q", root.n, path)
	}

	return nil
}

func (b *depspecBridge) ListPackages(id ProjectIdentifier, v Version) (pkgtree.PackageTree, error) {
	return b.sm.(fixSM).ListPackages(id, v)
}

func (b *depspecBridge) vendorCodeExists(id ProjectIdentifier) (bool, error) {
	return false, nil
}

// enforce interfaces
var _ Manifest = depspec{}
var _ Lock = dummyLock{}
var _ Lock = fixLock{}

// impl Spec interface
func (ds depspec) DependencyConstraints() ProjectConstraints {
	return pcSliceToMap(ds.deps)
}

type fixLock []LockedProject

// impl Lock interface
func (l fixLock) Projects() []LockedProject {
	return l
}

// impl Lock interface
func (fixLock) InputImports() []string {
	return nil
}

type dummyLock struct{}

// impl Lock interface
func (dummyLock) Projects() []LockedProject {
	return nil
}

// impl Lock interface
func (dummyLock) InputImports() []string {
	return nil
}
