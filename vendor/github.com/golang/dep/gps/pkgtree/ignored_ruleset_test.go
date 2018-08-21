// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkgtree

import "testing"

func TestIgnoredRuleset(t *testing.T) {
	type tfixm []struct {
		path string
		wild bool
	}
	cases := []struct {
		name            string
		inputs          []string
		wantInTree      tfixm
		wantEmptyTree   bool
		shouldIgnore    []string
		shouldNotIgnore []string
	}{
		{
			name:          "only skip global ignore",
			inputs:        []string{"*"},
			wantEmptyTree: true,
		},
		{
			name: "ignores without ignore suffix",
			inputs: []string{
				"x/y/z",
				"*a/b/c",
				"gophers",
			},
			wantInTree: tfixm{
				{path: "x/y/z", wild: false},
				{path: "*a/b/c", wild: false},
				{path: "gophers", wild: false},
			},
			shouldIgnore: []string{
				"x/y/z",
				"gophers",
			},
			shouldNotIgnore: []string{
				"x/y/z/q",
				"x/y",
				"gopher",
				"gopherss",
			},
		},
		{
			name: "ignores with ignore suffix",
			inputs: []string{
				"x/y/z*",
				"a/b/c",
				"gophers",
			},
			wantInTree: tfixm{
				{path: "x/y/z", wild: true},
				{path: "a/b/c", wild: false},
				{path: "gophers", wild: false},
			},
			shouldIgnore: []string{
				"x/y/z",
				"x/y/zz",
				"x/y/z/",
				"x/y/z/q",
			},
			shouldNotIgnore: []string{
				"x/y",
				"gopher",
			},
		},
		{
			name: "global ignore with other strings",
			inputs: []string{
				"*",
				"gophers*",
				"x/y/z*",
				"a/b/c",
			},
			wantInTree: tfixm{
				{path: "x/y/z", wild: true},
				{path: "a/b/c", wild: false},
				{path: "gophers", wild: true},
			},
			shouldIgnore: []string{
				"x/y/z",
				"x/y/z/",
				"x/y/z/q",
				"gophers",
				"gopherss",
				"gophers/foo",
			},
			shouldNotIgnore: []string{
				"x/y",
				"gopher",
			},
		},
		{
			name: "ineffectual ignore with wildcard",
			inputs: []string{
				"a/b*",
				"a/b/c*",
				"a/b/x/y",
				"a/c*",
			},
			wantInTree: tfixm{
				{path: "a/c", wild: true},
				{path: "a/b", wild: true},
			},
			shouldIgnore: []string{
				"a/cb",
			},
			shouldNotIgnore: []string{
				"a/",
				"a/d",
			},
		},
		{
			name: "same path with and without wildcard",
			inputs: []string{
				"a/b*",
				"a/b",
			},
			wantInTree: tfixm{
				{path: "a/b", wild: true},
			},
			shouldIgnore: []string{
				"a/b",
				"a/bb",
			},
			shouldNotIgnore: []string{
				"a/",
				"a/d",
			},
		},
		{
			name: "empty paths",
			inputs: []string{
				"",
				"a/b*",
			},
			wantInTree: tfixm{
				{path: "a/b", wild: true},
			},
			shouldNotIgnore: []string{
				"",
			},
		},
		{
			name: "single wildcard",
			inputs: []string{
				"a/b*",
			},
			wantInTree: tfixm{
				{path: "a/b", wild: true},
			},
			shouldIgnore: []string{
				"a/b/c",
			},
		},
	}

	for _, c := range cases {
		igm := NewIgnoredRuleset(c.inputs)
		f := func(t *testing.T) {

			if c.wantEmptyTree {
				if igm.Len() != 0 {
					t.Fatalf("wanted empty tree, but had %v elements", igm.Len())
				}
			}

			// Check if the wildcard suffix ignores are in the tree.
			for _, p := range c.wantInTree {
				wildi, has := igm.t.Get(p.path)
				if !has {
					t.Fatalf("expected %q to be in the tree", p.path)
				} else if wildi.(bool) != p.wild {
					if p.wild {
						t.Fatalf("expected %q to be a wildcard matcher, but it was not", p.path)
					} else {
						t.Fatalf("expected %q not to be a wildcard matcher, but it was", p.path)
					}
				}
			}

			for _, p := range c.shouldIgnore {
				if !igm.IsIgnored(p) {
					t.Fatalf("%q should be ignored, but it was not", p)
				}
			}
			for _, p := range c.shouldNotIgnore {
				if igm.IsIgnored(p) {
					t.Fatalf("%q should not be ignored, but it was", p)
				}
			}
		}
		t.Run(c.name, f)

		igm = NewIgnoredRuleset(igm.ToSlice())
		t.Run(c.name+"/inandout", f)
	}
}
