// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"reflect"
	"testing"

	"github.com/golang/dep/internal/test"
)

func TestEmptyProject(t *testing.T) {
	h := test.NewHelper(t)
	h.Parallel()
	defer h.Cleanup()

	g := new(graphviz).New()

	b := g.output("")
	want := h.GetTestFileString("graphviz/empty.dot")

	if b.String() != want {
		t.Fatalf("expected '%v', got '%v'", want, b.String())
	}
}

func TestSimpleProject(t *testing.T) {
	h := test.NewHelper(t)
	h.Parallel()
	defer h.Cleanup()

	g := new(graphviz).New()

	g.createNode("project", "", []string{"foo", "bar"})
	g.createNode("foo", "master", []string{"bar"})
	g.createNode("bar", "dev", []string{})

	b := g.output("")
	want := h.GetTestFileString("graphviz/case1.dot")
	if b.String() != want {
		t.Fatalf("expected '%v', got '%v'", want, b.String())
	}
}

func TestNoLinks(t *testing.T) {
	h := test.NewHelper(t)
	h.Parallel()
	defer h.Cleanup()

	g := new(graphviz).New()

	g.createNode("project", "", []string{})

	b := g.output("")
	want := h.GetTestFileString("graphviz/case2.dot")
	if b.String() != want {
		t.Fatalf("expected '%v', got '%v'", want, b.String())
	}
}

func TestIsPathPrefix(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		path string
		pre  string
		want bool
	}{
		{"github.com/sdboyer/foo/bar", "github.com/sdboyer/foo", true},
		{"github.com/sdboyer/foobar", "github.com/sdboyer/foo", false},
		{"github.com/sdboyer/bar/foo", "github.com/sdboyer/foo", false},
		{"golang.org/sdboyer/bar/foo", "github.com/sdboyer/foo", false},
		{"golang.org/sdboyer/FOO", "github.com/sdboyer/foo", false},
	}

	for _, tc := range tcs {
		r := isPathPrefix(tc.path, tc.pre)
		if tc.want != r {
			t.Fatalf("expected '%v', got '%v'", tc.want, r)
		}
	}
}

func TestSimpleSubgraphs(t *testing.T) {
	type testProject struct {
		name     string
		packages map[string][]string
	}

	testCases := []struct {
		name          string
		projects      []testProject
		targetProject string
		outputfile    string
	}{
		{
			name: "simple graph",
			projects: []testProject{
				{
					name: "ProjectA",
					packages: map[string][]string{
						"ProjectA/pkgX": []string{"ProjectC/pkgZ", "ProjectB/pkgX"},
						"ProjectA/pkgY": []string{"ProjectC/pkgX"},
					},
				},
				{
					name: "ProjectB",
					packages: map[string][]string{
						"ProjectB/pkgX": []string{},
						"ProjectB/pkgY": []string{"ProjectA/pkgY", "ProjectC/pkgZ"},
					},
				},
				{
					name: "ProjectC",
					packages: map[string][]string{
						"ProjectC/pkgX": []string{},
						"ProjectC/pkgY": []string{},
						"ProjectC/pkgZ": []string{},
					},
				},
			},
			targetProject: "ProjectC",
			outputfile:    "graphviz/subgraph1.dot",
		},
		{
			name: "edges from and to root projects",
			projects: []testProject{
				{
					name: "ProjectB",
					packages: map[string][]string{
						"ProjectB":      []string{"ProjectC/pkgX", "ProjectC"},
						"ProjectB/pkgX": []string{},
						"ProjectB/pkgY": []string{"ProjectA/pkgY", "ProjectC/pkgZ"},
						"ProjectB/pkgZ": []string{"ProjectC"},
					},
				},
				{
					name: "ProjectC",
					packages: map[string][]string{
						"ProjectC/pkgX": []string{},
						"ProjectC/pkgY": []string{},
						"ProjectC/pkgZ": []string{},
					},
				},
			},
			targetProject: "ProjectC",
			outputfile:    "graphviz/subgraph2.dot",
		},
		{
			name: "multi and single package projects",
			projects: []testProject{
				{
					name: "ProjectA",
					packages: map[string][]string{
						"ProjectA": []string{"ProjectC/pkgX"},
					},
				},
				{
					name: "ProjectB",
					packages: map[string][]string{
						"ProjectB":      []string{"ProjectC/pkgX", "ProjectC"},
						"ProjectB/pkgX": []string{},
						"ProjectB/pkgY": []string{"ProjectA/pkgY", "ProjectC/pkgZ"},
						"ProjectB/pkgZ": []string{"ProjectC"},
					},
				},
				{
					name: "ProjectC",
					packages: map[string][]string{
						"ProjectC/pkgX": []string{},
						"ProjectC/pkgY": []string{},
						"ProjectC/pkgZ": []string{},
					},
				},
			},
			targetProject: "ProjectC",
			outputfile:    "graphviz/subgraph3.dot",
		},
		{
			name: "relation from a cluster to a node",
			projects: []testProject{
				{
					name: "ProjectB",
					packages: map[string][]string{
						"ProjectB":      []string{"ProjectC/pkgX", "ProjectA"},
						"ProjectB/pkgX": []string{},
						"ProjectB/pkgY": []string{"ProjectA", "ProjectC/pkgZ"},
						"ProjectB/pkgZ": []string{"ProjectC"},
					},
				},
				{
					name: "ProjectA",
					packages: map[string][]string{
						"ProjectA": []string{"ProjectC/pkgX"},
					},
				},
			},
			targetProject: "ProjectA",
			outputfile:    "graphviz/subgraph4.dot",
		},
	}

	h := test.NewHelper(t)
	h.Parallel()
	defer h.Cleanup()

	for _, tc := range testCases {
		g := new(graphviz).New()

		for _, project := range tc.projects {
			g.createSubgraph(project.name, project.packages)
		}

		output := g.output(tc.targetProject)
		want := h.GetTestFileString(tc.outputfile)
		if output.String() != want {
			t.Fatalf("expected '%v', got '%v'", want, output.String())
		}
	}
}

func TestCreateSubgraph(t *testing.T) {
	testCases := []struct {
		name         string
		project      string
		pkgs         map[string][]string
		wantNodes    []*gvnode
		wantClusters map[string]*gvsubgraph
	}{
		{
			name:    "Project with subpackages",
			project: "ProjectA",
			pkgs: map[string][]string{
				"ProjectA/pkgX": []string{"ProjectC/pkgZ", "ProjectB/pkgX"},
				"ProjectA/pkgY": []string{"ProjectC/pkgX"},
			},
			wantNodes: []*gvnode{
				&gvnode{
					project:  "ProjectA/pkgX",
					children: []string{"ProjectC/pkgZ", "ProjectB/pkgX"},
				},
				&gvnode{
					project:  "ProjectA/pkgY",
					children: []string{"ProjectC/pkgX"},
				},
			},
			wantClusters: map[string]*gvsubgraph{
				"ProjectA": &gvsubgraph{
					project:  "ProjectA",
					packages: []string{"ProjectA/pkgX", "ProjectA/pkgY"},
					index:    0,
					children: []string{},
				},
			},
		},
		{
			name:    "Project with single subpackage at root",
			project: "ProjectA",
			pkgs: map[string][]string{
				"ProjectA": []string{"ProjectC/pkgZ", "ProjectB/pkgX"},
			},
			wantNodes: []*gvnode{
				&gvnode{
					project:  "ProjectA",
					children: []string{"ProjectC/pkgZ", "ProjectB/pkgX"},
				},
			},
			wantClusters: map[string]*gvsubgraph{},
		},
		{
			name:    "Project with subpackages and no children",
			project: "ProjectX",
			pkgs: map[string][]string{
				"ProjectX/pkgA": []string{},
			},
			wantNodes: []*gvnode{
				&gvnode{
					project:  "ProjectX/pkgA",
					children: []string{},
				},
			},
			wantClusters: map[string]*gvsubgraph{
				"ProjectX": &gvsubgraph{
					project:  "ProjectX",
					packages: []string{"ProjectX/pkgA"},
					index:    0,
					children: []string{},
				},
			},
		},
		{
			name:    "Project with subpackage and root package with children",
			project: "ProjectA",
			pkgs: map[string][]string{
				"ProjectA":      []string{"ProjectC/pkgZ", "ProjectB/pkgX"},
				"ProjectA/pkgX": []string{"ProjectC/pkgA"},
			},
			wantNodes: []*gvnode{
				&gvnode{
					project:  "ProjectA/pkgX",
					children: []string{"ProjectC/pkgA"},
				},
			},
			wantClusters: map[string]*gvsubgraph{
				"ProjectA": &gvsubgraph{
					project:  "ProjectA",
					packages: []string{"ProjectA/pkgX"},
					index:    0,
					children: []string{"ProjectC/pkgZ", "ProjectB/pkgX"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := new(graphviz).New()

			g.createSubgraph(tc.project, tc.pkgs)

			// Check the number of created nodes.
			if len(g.ps) != len(tc.wantNodes) {
				t.Errorf("unexpected number of nodes: \n\t(GOT) %v\n\t(WNT) %v", len(g.ps), len(tc.wantNodes))
			}

			// Check if the expected nodes are created.
			for i, v := range tc.wantNodes {
				if v.project != g.ps[i].project {
					t.Errorf("found unexpected node: \n\t(GOT) %v\n\t(WNT) %v", g.ps[i].project, v.project)
				}
			}

			// Check the number of created clusters.
			if len(g.clusters) != len(tc.wantClusters) {
				t.Errorf("unexpected number of clusters: \n\t(GOT) %v\n\t(WNT) %v", len(g.clusters), len(tc.wantClusters))
			}

			// Check if the expected clusters are created.
			if !reflect.DeepEqual(g.clusters, tc.wantClusters) {
				t.Errorf("unexpected clusters: \n\t(GOT) %v\n\t(WNT) %v", g.clusters, tc.wantClusters)
			}
		})
	}
}
