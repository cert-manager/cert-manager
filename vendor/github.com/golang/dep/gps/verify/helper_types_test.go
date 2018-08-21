// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package verify

import (
	"github.com/golang/dep/gps"
	"github.com/golang/dep/gps/pkgtree"
)

// mkPI creates a ProjectIdentifier with the ProjectRoot as the provided
// string, and the Source unset.
//
// Call normalize() on the returned value if you need the Source to be be
// equal to the ProjectRoot.
func mkPI(root string) gps.ProjectIdentifier {
	return gps.ProjectIdentifier{
		ProjectRoot: gps.ProjectRoot(root),
	}
}

type safeLock struct {
	p []gps.LockedProject
	i []string
}

func (sl safeLock) InputImports() []string {
	return sl.i
}

func (sl safeLock) Projects() []gps.LockedProject {
	return sl.p
}

func (sl safeLock) dup() safeLock {
	sl2 := safeLock{
		i: make([]string, len(sl.i)),
		p: make([]gps.LockedProject, 0, len(sl.p)),
	}
	copy(sl2.i, sl.i)

	for _, lp := range sl.p {
		// Only for use with VerifiableProjects.
		sl2.p = append(sl2.p, lp.(VerifiableProject).dup())
	}

	return sl2
}

func (vp VerifiableProject) dup() VerifiableProject {
	pkglist := make([]string, len(vp.Packages()))
	copy(pkglist, vp.Packages())
	hashbytes := make([]byte, len(vp.Digest.Digest))
	copy(hashbytes, vp.Digest.Digest)

	return VerifiableProject{
		LockedProject: gps.NewLockedProject(vp.Ident(), vp.Version(), pkglist),
		PruneOpts:     vp.PruneOpts,
		Digest: VersionedDigest{
			HashVersion: vp.Digest.HashVersion,
			Digest:      hashbytes,
		},
	}
}

// simpleRootManifest exists so that we have a safe value to swap into solver
// params when a nil Manifest is provided.
type simpleRootManifest struct {
	c, ovr gps.ProjectConstraints
	ig     *pkgtree.IgnoredRuleset
	req    map[string]bool
}

func (m simpleRootManifest) DependencyConstraints() gps.ProjectConstraints {
	return m.c
}
func (m simpleRootManifest) Overrides() gps.ProjectConstraints {
	return m.ovr
}
func (m simpleRootManifest) IgnoredPackages() *pkgtree.IgnoredRuleset {
	return m.ig
}
func (m simpleRootManifest) RequiredPackages() map[string]bool {
	return m.req
}

func (m simpleRootManifest) dup() simpleRootManifest {
	m2 := simpleRootManifest{
		c:   make(gps.ProjectConstraints),
		ovr: make(gps.ProjectConstraints),
		ig:  pkgtree.NewIgnoredRuleset(m.ig.ToSlice()),
		req: make(map[string]bool),
	}

	for k, v := range m.c {
		m2.c[k] = v
	}

	for k, v := range m.ovr {
		m2.ovr[k] = v
	}

	for k := range m.req {
		m2.req[k] = true
	}

	return m2
}

func newVerifiableProject(id gps.ProjectIdentifier, v gps.Version, pkgs []string) VerifiableProject {
	return VerifiableProject{
		LockedProject: gps.NewLockedProject(id, v, pkgs),
		Digest: VersionedDigest{
			HashVersion: HashVersion,
			Digest:      []byte("something"),
		},
	}
}
