// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package verify

import (
	"strings"
	"testing"

	"github.com/golang/dep/gps"
	"github.com/golang/dep/gps/pkgtree"
)

type lockUnsatisfactionDimension uint8

const (
	noLock lockUnsatisfactionDimension = 1 << iota
	missingImports
	excessImports
	unmatchedOverrides
	unmatchedConstraints
)

func (lsd lockUnsatisfactionDimension) String() string {
	var parts []string
	for i := uint(0); i < 5; i++ {
		if lsd&(1<<i) != 0 {
			switch lsd {
			case noLock:
				parts = append(parts, "no lock")
			case missingImports:
				parts = append(parts, "missing imports")
			case excessImports:
				parts = append(parts, "excess imports")
			case unmatchedOverrides:
				parts = append(parts, "unmatched overrides")
			case unmatchedConstraints:
				parts = append(parts, "unmatched constraints")
			}
		}
	}

	return strings.Join(parts, ", ")
}

func TestLockSatisfaction(t *testing.T) {
	fooversion := gps.NewVersion("v1.0.0").Pair("foorev1")
	bazversion := gps.NewVersion("v2.0.0").Pair("bazrev1")
	transver := gps.NewVersion("v0.5.0").Pair("transrev1")
	l := safeLock{
		i: []string{"foo.com/bar", "baz.com/qux"},
		p: []gps.LockedProject{
			newVerifiableProject(mkPI("foo.com/bar"), fooversion, []string{".", "subpkg"}),
			newVerifiableProject(mkPI("baz.com/qux"), bazversion, []string{".", "other"}),
			newVerifiableProject(mkPI("transitive.com/dependency"), transver, []string{"."}),
		},
	}

	ptree := pkgtree.PackageTree{
		ImportRoot: "current",
		Packages: map[string]pkgtree.PackageOrErr{
			"current": {
				P: pkgtree.Package{
					Name:       "current",
					ImportPath: "current",
					Imports:    []string{"foo.com/bar"},
				},
			},
		},
	}
	rm := simpleRootManifest{
		req: map[string]bool{
			"baz.com/qux": true,
		},
	}

	var dup rootManifestTransformer = func(simpleRootManifest) simpleRootManifest {
		return rm.dup()
	}

	tt := map[string]struct {
		rmt     rootManifestTransformer
		sat     lockUnsatisfactionDimension
		checkfn func(*testing.T, LockSatisfaction)
	}{
		"ident": {
			rmt: dup,
		},
		"added import": {
			rmt: dup.addReq("fiz.com/wow"),
			sat: missingImports,
		},
		"removed import": {
			rmt: dup.rmReq("baz.com/qux"),
			sat: excessImports,
		},
		"added and removed import": {
			rmt: dup.rmReq("baz.com/qux").addReq("fiz.com/wow"),
			sat: excessImports | missingImports,
			checkfn: func(t *testing.T, lsat LockSatisfaction) {
				if lsat.MissingImports[0] != "fiz.com/wow" {
					t.Errorf("expected 'fiz.com/wow' as sole missing import, got %s", lsat.MissingImports)
				}
				if lsat.ExcessImports[0] != "baz.com/qux" {
					t.Errorf("expected 'baz.com/qux' as sole excess import, got %s", lsat.ExcessImports)
				}
			},
		},
		"acceptable constraint": {
			rmt: dup.setConstraint("baz.com/qux", bazversion.Unpair(), ""),
		},
		"unacceptable constraint": {
			rmt: dup.setConstraint("baz.com/qux", fooversion.Unpair(), ""),
			sat: unmatchedConstraints,
			checkfn: func(t *testing.T, lsat LockSatisfaction) {
				pr := gps.ProjectRoot("baz.com/qux")
				unmet, has := lsat.UnmetConstraints[pr]
				if !has {
					t.Errorf("did not have constraint on expected project %q; map contents: %s", pr, lsat.UnmetConstraints)
				}

				if unmet.C != fooversion.Unpair() {
					t.Errorf("wanted %s for unmet constraint, got %s", fooversion.Unpair(), unmet.C)
				}

				if unmet.V != bazversion {
					t.Errorf("wanted %s for version that did not meet constraint, got %s", bazversion, unmet.V)
				}
			},
		},
		"acceptable override": {
			rmt: dup.setOverride("baz.com/qux", bazversion.Unpair(), ""),
		},
		"unacceptable override": {
			rmt: dup.setOverride("baz.com/qux", fooversion.Unpair(), ""),
			sat: unmatchedOverrides,
		},
		"ineffectual constraint": {
			rmt: dup.setConstraint("transitive.com/dependency", bazversion.Unpair(), ""),
		},
		"transitive override": {
			rmt: dup.setOverride("transitive.com/dependency", bazversion.Unpair(), ""),
			sat: unmatchedOverrides,
		},
		"ignores respected": {
			rmt: dup.addIgnore("foo.com/bar"),
			sat: excessImports,
		},
	}

	for name, fix := range tt {
		fix := fix
		t.Run(name, func(t *testing.T) {
			fixrm := fix.rmt(rm)
			lsat := LockSatisfiesInputs(l, fixrm, ptree)

			gotsat := lsat.unsatTypes()
			if fix.sat & ^gotsat != 0 {
				t.Errorf("wanted unsat in some dimensions that were satisfied: %s", fix.sat & ^gotsat)
			}
			if gotsat & ^fix.sat != 0 {
				t.Errorf("wanted sat in some dimensions that were unsatisfied: %s", gotsat & ^fix.sat)
			}

			if lsat.Satisfied() && fix.sat != 0 {
				t.Errorf("Satisfied() incorrectly reporting true when expecting some dimensions to be unsatisfied: %s", fix.sat)
			} else if !lsat.Satisfied() && fix.sat == 0 {
				t.Error("Satisfied() incorrectly reporting false when expecting all dimensions to be satisfied")
			}

			if fix.checkfn != nil {
				fix.checkfn(t, lsat)
			}
		})
	}

	var lsat LockSatisfaction
	if lsat.Satisfied() {
		t.Error("zero value of LockSatisfaction should fail")
	}
	if LockSatisfiesInputs(nil, nil, ptree).Satisfied() {
		t.Error("nil lock to LockSatisfiesInputs should produce failing result")
	}
}

func (ls LockSatisfaction) unsatTypes() lockUnsatisfactionDimension {
	var dims lockUnsatisfactionDimension

	if !ls.LockExisted {
		dims |= noLock
	}
	if len(ls.MissingImports) != 0 {
		dims |= missingImports
	}
	if len(ls.ExcessImports) != 0 {
		dims |= excessImports
	}
	if len(ls.UnmetOverrides) != 0 {
		dims |= unmatchedOverrides
	}
	if len(ls.UnmetConstraints) != 0 {
		dims |= unmatchedConstraints
	}

	return dims
}

type rootManifestTransformer func(simpleRootManifest) simpleRootManifest

func (rmt rootManifestTransformer) compose(rmt2 rootManifestTransformer) rootManifestTransformer {
	if rmt == nil {
		return rmt2
	}
	return func(rm simpleRootManifest) simpleRootManifest {
		return rmt2(rmt(rm))
	}
}

func (rmt rootManifestTransformer) addReq(path string) rootManifestTransformer {
	return rmt.compose(func(rm simpleRootManifest) simpleRootManifest {
		rm.req[path] = true
		return rm
	})
}

func (rmt rootManifestTransformer) rmReq(path string) rootManifestTransformer {
	return rmt.compose(func(rm simpleRootManifest) simpleRootManifest {
		delete(rm.req, path)
		return rm
	})
}

func (rmt rootManifestTransformer) setConstraint(pr string, c gps.Constraint, source string) rootManifestTransformer {
	return rmt.compose(func(rm simpleRootManifest) simpleRootManifest {
		rm.c[gps.ProjectRoot(pr)] = gps.ProjectProperties{
			Constraint: c,
			Source:     source,
		}
		return rm
	})
}

func (rmt rootManifestTransformer) setOverride(pr string, c gps.Constraint, source string) rootManifestTransformer {
	return rmt.compose(func(rm simpleRootManifest) simpleRootManifest {
		rm.ovr[gps.ProjectRoot(pr)] = gps.ProjectProperties{
			Constraint: c,
			Source:     source,
		}
		return rm
	})
}

func (rmt rootManifestTransformer) addIgnore(path string) rootManifestTransformer {
	return rmt.compose(func(rm simpleRootManifest) simpleRootManifest {
		rm.ig = pkgtree.NewIgnoredRuleset(append(rm.ig.ToSlice(), path))
		return rm
	})
}
