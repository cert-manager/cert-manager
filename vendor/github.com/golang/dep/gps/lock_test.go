// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"reflect"
	"sort"
	"testing"
)

func TestLockedProjectSorting(t *testing.T) {
	// version doesn't matter here
	lps := []LockedProject{
		NewLockedProject(mkPI("github.com/sdboyer/gps"), NewVersion("v0.10.0"), nil),
		NewLockedProject(mkPI("foo"), NewVersion("nada"), nil),
		NewLockedProject(mkPI("bar"), NewVersion("zip"), nil),
		NewLockedProject(mkPI("qux"), NewVersion("zilch"), nil),
	}
	lps2 := make([]LockedProject, len(lps))
	copy(lps2, lps)

	sort.SliceStable(lps2, func(i, j int) bool {
		return lps2[i].Ident().Less(lps2[j].Ident())
	})

	// only the two should have switched positions
	lps[0], lps[2] = lps[2], lps[0]
	if !reflect.DeepEqual(lps, lps2) {
		t.Errorf("SortLockedProject did not sort as expected:\n\t(GOT) %s\n\t(WNT) %s", lps2, lps)
	}
}

func TestLockedProjectsEq(t *testing.T) {
	lps := []LockedProject{
		NewLockedProject(mkPI("github.com/sdboyer/gps"), NewVersion("v0.10.0").Pair("REV"), []string{"gps"}),
		NewLockedProject(mkPI("github.com/sdboyer/gps"), NewVersion("v0.10.0").Pair("REV"), nil),
		NewLockedProject(mkPI("github.com/sdboyer/gps"), NewVersion("v0.10.0").Pair("REV"), []string{"gps", "flugle"}),
		NewLockedProject(mkPI("foo"), NewVersion("nada").Pair("OTHERREV"), []string{"foo"}),
		NewLockedProject(mkPI("github.com/sdboyer/gps"), NewVersion("v0.10.0").Pair("REV"), []string{"flugle", "gps"}),
		NewLockedProject(mkPI("github.com/sdboyer/gps"), NewVersion("v0.10.0").Pair("REV2"), []string{"gps"}),
		NewLockedProject(mkPI("github.com/sdboyer/gps"), NewVersion("v0.11.0").Pair("REV"), []string{"gps"}),
		NewLockedProject(mkPI("github.com/sdboyer/gps"), Revision("REV2"), []string{"gps"}),
	}

	fix := map[string]struct {
		l1, l2   int
		shouldeq bool
		err      string
	}{
		"with self":               {0, 0, true, "lp does not eq self"},
		"with different revision": {0, 5, false, "should not eq with different rev"},
		"with different versions": {0, 6, false, "should not eq with different version"},
		"with same revsion":       {5, 5, true, "should eq with same rev"},
		"with empty pkg":          {0, 1, false, "should not eq when other pkg list is empty"},
		"with long pkg list":      {0, 2, false, "should not eq when other pkg list is longer"},
		"with different orders":   {2, 4, false, "should not eq when pkg lists are out of order"},
		"with different lp":       {0, 3, false, "should not eq totally different lp"},
		"with only rev":           {7, 7, true, "should eq with only rev"},
		"when only rev matches":   {5, 7, false, "should not eq when only rev matches"},
	}

	for k, f := range fix {
		k, f := k, f
		t.Run(k, func(t *testing.T) {
			if f.shouldeq {
				if !lps[f.l1].Eq(lps[f.l2]) {
					t.Error(f.err)
				}
				if !lps[f.l2].Eq(lps[f.l1]) {
					t.Error(f.err + (" (reversed)"))
				}
			} else {
				if lps[f.l1].Eq(lps[f.l2]) {
					t.Error(f.err)
				}
				if lps[f.l2].Eq(lps[f.l1]) {
					t.Error(f.err + (" (reversed)"))
				}
			}
		})
	}
}

func TestLockedProjectsString(t *testing.T) {
	tt := []struct {
		name string
		lp   LockedProject
		want string
	}{
		{
			name: "full info",
			lp:   NewLockedProject(mkPI("github.com/sdboyer/gps"), NewVersion("v0.10.0"), []string{"gps"}),
			want: "github.com/sdboyer/gps@v0.10.0 with packages: [gps]",
		},
		{
			name: "empty package list",
			lp:   NewLockedProject(mkPI("github.com/sdboyer/gps"), NewVersion("v0.10.0"), []string{}),
			want: "github.com/sdboyer/gps@v0.10.0 with packages: []",
		},
		{
			name: "nil package",
			lp:   NewLockedProject(mkPI("github.com/sdboyer/gps"), NewVersion("v0.10.0"), nil),
			want: "github.com/sdboyer/gps@v0.10.0 with packages: []",
		},
		{
			name: "with source",
			lp: NewLockedProject(
				ProjectIdentifier{ProjectRoot: "github.com/sdboyer/gps", Source: "github.com/another/repo"},
				NewVersion("v0.10.0"), []string{"."}),
			want: "github.com/sdboyer/gps (from github.com/another/repo)@v0.10.0 with packages: [.]",
		},
		{
			name: "version pair",
			lp:   NewLockedProject(mkPI("github.com/sdboyer/gps"), NewVersion("v0.10.0").Pair("278a227dfc3d595a33a77ff3f841fd8ca1bc8cd0"), []string{"gps"}),
			want: "github.com/sdboyer/gps@v0.10.0 with packages: [gps]",
		},
		{
			name: "revision only",
			lp:   NewLockedProject(mkPI("github.com/sdboyer/gps"), Revision("278a227dfc3d595a33a77ff3f841fd8ca1bc8cd0"), []string{"gps"}),
			want: "github.com/sdboyer/gps@278a227dfc3d595a33a77ff3f841fd8ca1bc8cd0 with packages: [gps]",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.lp.String()
			if tc.want != s {
				t.Fatalf("want %s, got %s", tc.want, s)
			}
		})
	}

}
