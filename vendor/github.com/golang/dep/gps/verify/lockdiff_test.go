// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package verify

import (
	"fmt"
	"math/bits"
	"strings"
	"testing"

	"github.com/golang/dep/gps"
)

func contains(haystack []string, needle string) bool {
	for _, str := range haystack {
		if str == needle {
			return true
		}
	}
	return false
}

func (dd DeltaDimension) String() string {
	var parts []string

	for dd != 0 {
		index := bits.TrailingZeros32(uint32(dd))
		dd &= ^(1 << uint(index))

		switch DeltaDimension(1 << uint(index)) {
		case InputImportsChanged:
			parts = append(parts, "input imports")
		case ProjectAdded:
			parts = append(parts, "project added")
		case ProjectRemoved:
			parts = append(parts, "project removed")
		case SourceChanged:
			parts = append(parts, "source changed")
		case VersionChanged:
			parts = append(parts, "version changed")
		case RevisionChanged:
			parts = append(parts, "revision changed")
		case PackagesChanged:
			parts = append(parts, "packages changed")
		case PruneOptsChanged:
			parts = append(parts, "pruneopts changed")
		case HashVersionChanged:
			parts = append(parts, "hash version changed")
		case HashChanged:
			parts = append(parts, "hash digest changed")
		}
	}

	return strings.Join(parts, ", ")
}

func TestLockDelta(t *testing.T) {
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

	var dup lockTransformer = func(l safeLock) safeLock {
		return l.dup()
	}

	tt := map[string]struct {
		lt      lockTransformer
		delta   DeltaDimension
		checkfn func(*testing.T, LockDelta)
	}{
		"ident": {
			lt: dup,
		},
		"added import": {
			lt:    dup.addII("other.org"),
			delta: InputImportsChanged,
		},
		"added import 2x": {
			lt:    dup.addII("other.org").addII("andsomethingelse.com/wowie"),
			delta: InputImportsChanged,
			checkfn: func(t *testing.T, ld LockDelta) {
				if !contains(ld.AddedImportInputs, "other.org") {
					t.Error("first added input import missing")
				}
				if !contains(ld.AddedImportInputs, "andsomethingelse.com/wowie") {
					t.Error("first added input import missing")
				}
			},
		},
		"removed import": {
			lt:    dup.rmII("baz.com/qux"),
			delta: InputImportsChanged,
			checkfn: func(t *testing.T, ld LockDelta) {
				if !contains(ld.RemovedImportInputs, "baz.com/qux") {
					t.Error("removed input import missing")
				}
			},
		},
		"add project": {
			lt:    dup.addDumbProject("madeup.org"),
			delta: ProjectAdded,
		},
		"remove project": {
			lt:    dup.rmProject("foo.com/bar"),
			delta: ProjectRemoved,
		},
		"all": {
			lt:    dup.addII("other.org").rmII("baz.com/qux").addDumbProject("zebrafun.org").rmProject("foo.com/bar"),
			delta: InputImportsChanged | ProjectRemoved | ProjectAdded,
		},
	}

	for name, fix := range tt {
		fix := fix
		t.Run(name, func(t *testing.T) {
			fixl := fix.lt(l)
			ld := DiffLocks(l, fixl)

			if !ld.Changed(AnyChanged) && fix.delta != 0 {
				t.Errorf("Changed() reported false when expecting some dimensions to be changed: %s", fix.delta)
			} else if ld.Changed(AnyChanged) && fix.delta == 0 {
				t.Error("Changed() reported true when expecting no changes")
			}
			if ld.Changed(AnyChanged & ^fix.delta) {
				t.Errorf("Changed() reported true when checking along not-expected dimensions: %s", ld.Changes() & ^fix.delta)
			}

			gotdelta := ld.Changes()
			if fix.delta & ^gotdelta != 0 {
				t.Errorf("wanted change in some dimensions that were unchanged: %s", fix.delta & ^gotdelta)
			}
			if gotdelta & ^fix.delta != 0 {
				t.Errorf("did not want change in some dimensions that were changed: %s", gotdelta & ^fix.delta)
			}

			if fix.checkfn != nil {
				fix.checkfn(t, ld)
			}
		})
	}
}

func TestLockedProjectPropertiesDelta(t *testing.T) {
	fooversion, foorev := gps.NewVersion("v1.0.0"), gps.Revision("foorev1")
	foopair := fooversion.Pair(foorev)
	foovp := VerifiableProject{
		LockedProject: gps.NewLockedProject(mkPI("foo.com/project"), foopair, []string{".", "subpkg"}),
		PruneOpts:     gps.PruneNestedVendorDirs,
		Digest: VersionedDigest{
			HashVersion: HashVersion,
			Digest:      []byte("foobytes"),
		},
	}
	var dup lockedProjectTransformer = func(lp gps.LockedProject) gps.LockedProject {
		return lp.(VerifiableProject).dup()
	}

	tt := map[string]struct {
		lt1, lt2 lockedProjectTransformer
		delta    DeltaDimension
		checkfn  func(*testing.T, LockedProjectPropertiesDelta)
	}{
		"ident": {
			lt1: dup,
		},
		"add pkg": {
			lt1:   dup.addPkg("whatev"),
			delta: PackagesChanged,
		},
		"rm pkg": {
			lt1:   dup.rmPkg("subpkg"),
			delta: PackagesChanged,
		},
		"add and rm pkg": {
			lt1:   dup.rmPkg("subpkg").addPkg("whatev"),
			delta: PackagesChanged,
			checkfn: func(t *testing.T, ld LockedProjectPropertiesDelta) {
				if !contains(ld.PackagesAdded, "whatev") {
					t.Error("added pkg missing from list")
				}
				if !contains(ld.PackagesRemoved, "subpkg") {
					t.Error("removed pkg missing from list")
				}
			},
		},
		"add source": {
			lt1:   dup.setSource("somethingelse"),
			delta: SourceChanged,
		},
		"remove source": {
			lt1:   dup.setSource("somethingelse"),
			lt2:   dup,
			delta: SourceChanged,
		},
		"to rev only": {
			lt1:   dup.setVersion(foorev),
			delta: VersionChanged,
		},
		"from rev only": {
			lt1:   dup.setVersion(foorev),
			lt2:   dup,
			delta: VersionChanged,
		},
		"to new rev only": {
			lt1:   dup.setVersion(gps.Revision("newrev")),
			delta: VersionChanged | RevisionChanged,
		},
		"from new rev only": {
			lt1:   dup.setVersion(gps.Revision("newrev")),
			lt2:   dup,
			delta: VersionChanged | RevisionChanged,
		},
		"version change": {
			lt1:   dup.setVersion(gps.NewVersion("v0.5.0").Pair(foorev)),
			delta: VersionChanged,
		},
		"version change to norev": {
			lt1:   dup.setVersion(gps.NewVersion("v0.5.0")),
			delta: VersionChanged | RevisionChanged,
		},
		"version change from norev": {
			lt1:   dup.setVersion(gps.NewVersion("v0.5.0")),
			lt2:   dup.setVersion(gps.NewVersion("v0.5.0").Pair(foorev)),
			delta: RevisionChanged,
		},
		"to branch": {
			lt1:   dup.setVersion(gps.NewBranch("master").Pair(foorev)),
			delta: VersionChanged,
		},
		"to branch new rev": {
			lt1:   dup.setVersion(gps.NewBranch("master").Pair(gps.Revision("newrev"))),
			delta: VersionChanged | RevisionChanged,
		},
		"to empty prune opts": {
			lt1:   dup.setPruneOpts(0),
			delta: PruneOptsChanged,
		},
		"from empty prune opts": {
			lt1:   dup.setPruneOpts(0),
			lt2:   dup,
			delta: PruneOptsChanged,
		},
		"prune opts change": {
			lt1:   dup.setPruneOpts(gps.PruneNestedVendorDirs | gps.PruneNonGoFiles),
			delta: PruneOptsChanged,
		},
		"empty digest": {
			lt1:   dup.setDigest(VersionedDigest{}),
			delta: HashVersionChanged | HashChanged,
		},
		"to empty digest": {
			lt1:   dup.setDigest(VersionedDigest{}),
			lt2:   dup,
			delta: HashVersionChanged | HashChanged,
		},
		"hash version changed": {
			lt1:   dup.setDigest(VersionedDigest{HashVersion: HashVersion + 1, Digest: []byte("foobytes")}),
			delta: HashVersionChanged,
		},
		"hash contents changed": {
			lt1:   dup.setDigest(VersionedDigest{HashVersion: HashVersion, Digest: []byte("barbytes")}),
			delta: HashChanged,
		},
		"to plain locked project": {
			lt1:   dup.toPlainLP(),
			delta: PruneOptsChanged | HashChanged | HashVersionChanged,
		},
		"from plain locked project": {
			lt1:   dup.toPlainLP(),
			lt2:   dup,
			delta: PruneOptsChanged | HashChanged | HashVersionChanged,
		},
		"all": {
			lt1:   dup.setDigest(VersionedDigest{}).setVersion(gps.NewBranch("master").Pair(gps.Revision("newrev"))).setPruneOpts(gps.PruneNestedVendorDirs | gps.PruneNonGoFiles).setSource("whatever"),
			delta: SourceChanged | VersionChanged | RevisionChanged | PruneOptsChanged | HashChanged | HashVersionChanged,
		},
	}

	for name, fix := range tt {
		fix := fix
		t.Run(name, func(t *testing.T) {
			// Use two patterns for constructing locks to compare: if only lt1
			// is set, use foovp as the first lp and compare with the lt1
			// transforms applied. If lt2 is set, transform foovp with lt1 for
			// the first lp, then transform foovp with lt2 for the second lp.
			var lp1, lp2 gps.LockedProject
			if fix.lt2 == nil {
				lp1 = foovp
				lp2 = fix.lt1(foovp)
			} else {
				lp1 = fix.lt1(foovp)
				lp2 = fix.lt2(foovp)
			}

			lppd := DiffLockedProjectProperties(lp1, lp2)
			if !lppd.Changed(AnyChanged) && fix.delta != 0 {
				t.Errorf("Changed() reporting false when expecting some dimensions to be changed: %s", fix.delta)
			} else if lppd.Changed(AnyChanged) && fix.delta == 0 {
				t.Error("Changed() reporting true when expecting no changes")
			}
			if lppd.Changed(AnyChanged & ^fix.delta) {
				t.Errorf("Changed() reported true when checking along not-expected dimensions: %s", lppd.Changes() & ^fix.delta)
			}

			gotdelta := lppd.Changes()
			if fix.delta & ^gotdelta != 0 {
				t.Errorf("wanted change in some dimensions that were unchanged: %s", fix.delta & ^gotdelta)
			}
			if gotdelta & ^fix.delta != 0 {
				t.Errorf("did not want change in some dimensions that were changed: %s", gotdelta & ^fix.delta)
			}

			if fix.checkfn != nil {
				fix.checkfn(t, lppd)
			}
		})
	}
}

type lockTransformer func(safeLock) safeLock

func (lt lockTransformer) compose(lt2 lockTransformer) lockTransformer {
	if lt == nil {
		return lt2
	}
	return func(l safeLock) safeLock {
		return lt2(lt(l))
	}
}

func (lt lockTransformer) addDumbProject(root string) lockTransformer {
	vp := newVerifiableProject(mkPI(root), gps.NewVersion("whatever").Pair("addedrev"), []string{"."})
	return lt.compose(func(l safeLock) safeLock {
		for _, lp := range l.p {
			if lp.Ident().ProjectRoot == vp.Ident().ProjectRoot {
				panic(fmt.Sprintf("%q already in lock", vp.Ident().ProjectRoot))
			}
		}
		l.p = append(l.p, vp)
		return l
	})
}

func (lt lockTransformer) rmProject(pr string) lockTransformer {
	return lt.compose(func(l safeLock) safeLock {
		for k, lp := range l.p {
			if lp.Ident().ProjectRoot == gps.ProjectRoot(pr) {
				l.p = l.p[:k+copy(l.p[k:], l.p[k+1:])]
				return l
			}
		}
		panic(fmt.Sprintf("%q not in lock", pr))
	})
}

func (lt lockTransformer) addII(path string) lockTransformer {
	return lt.compose(func(l safeLock) safeLock {
		for _, impath := range l.i {
			if path == impath {
				panic(fmt.Sprintf("%q already in input imports", impath))
			}
		}
		l.i = append(l.i, path)
		return l
	})
}

func (lt lockTransformer) rmII(path string) lockTransformer {
	return lt.compose(func(l safeLock) safeLock {
		for k, impath := range l.i {
			if path == impath {
				l.i = l.i[:k+copy(l.i[k:], l.i[k+1:])]
				return l
			}
		}
		panic(fmt.Sprintf("%q not in input imports", path))
	})
}

type lockedProjectTransformer func(gps.LockedProject) gps.LockedProject

func (lpt lockedProjectTransformer) compose(lpt2 lockedProjectTransformer) lockedProjectTransformer {
	if lpt == nil {
		return lpt2
	}
	return func(lp gps.LockedProject) gps.LockedProject {
		return lpt2(lpt(lp))
	}
}

func (lpt lockedProjectTransformer) addPkg(path string) lockedProjectTransformer {
	return lpt.compose(func(lp gps.LockedProject) gps.LockedProject {
		for _, pkg := range lp.Packages() {
			if path == pkg {
				panic(fmt.Sprintf("%q already in pkg list", path))
			}
		}

		nlp := gps.NewLockedProject(lp.Ident(), lp.Version(), append(lp.Packages(), path))
		if vp, ok := lp.(VerifiableProject); ok {
			vp.LockedProject = nlp
			return vp
		}
		return nlp
	})
}

func (lpt lockedProjectTransformer) rmPkg(path string) lockedProjectTransformer {
	return lpt.compose(func(lp gps.LockedProject) gps.LockedProject {
		pkglist := lp.Packages()
		for k, pkg := range pkglist {
			if path == pkg {
				pkglist = pkglist[:k+copy(pkglist[k:], pkglist[k+1:])]
				nlp := gps.NewLockedProject(lp.Ident(), lp.Version(), pkglist)
				if vp, ok := lp.(VerifiableProject); ok {
					vp.LockedProject = nlp
					return vp
				}
				return nlp
			}
		}
		panic(fmt.Sprintf("%q not in pkg list", path))
	})
}

func (lpt lockedProjectTransformer) setSource(source string) lockedProjectTransformer {
	return lpt.compose(func(lp gps.LockedProject) gps.LockedProject {
		ident := lp.Ident()
		ident.Source = source
		nlp := gps.NewLockedProject(ident, lp.Version(), lp.Packages())
		if vp, ok := lp.(VerifiableProject); ok {
			vp.LockedProject = nlp
			return vp
		}
		return nlp
	})
}

func (lpt lockedProjectTransformer) setVersion(v gps.Version) lockedProjectTransformer {
	return lpt.compose(func(lp gps.LockedProject) gps.LockedProject {
		nlp := gps.NewLockedProject(lp.Ident(), v, lp.Packages())
		if vp, ok := lp.(VerifiableProject); ok {
			vp.LockedProject = nlp
			return vp
		}
		return nlp
	})
}

func (lpt lockedProjectTransformer) setPruneOpts(po gps.PruneOptions) lockedProjectTransformer {
	return lpt.compose(func(lp gps.LockedProject) gps.LockedProject {
		vp := lp.(VerifiableProject)
		vp.PruneOpts = po
		return vp
	})
}

func (lpt lockedProjectTransformer) setDigest(vd VersionedDigest) lockedProjectTransformer {
	return lpt.compose(func(lp gps.LockedProject) gps.LockedProject {
		vp := lp.(VerifiableProject)
		vp.Digest = vd
		return vp
	})
}

func (lpt lockedProjectTransformer) toPlainLP() lockedProjectTransformer {
	return lpt.compose(func(lp gps.LockedProject) gps.LockedProject {
		if vp, ok := lp.(VerifiableProject); ok {
			return vp.LockedProject
		}
		return lp
	})
}
