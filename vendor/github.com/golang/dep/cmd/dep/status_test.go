// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"text/tabwriter"
	"text/template"

	"io"

	"github.com/golang/dep"
	"github.com/golang/dep/gps"
	"github.com/golang/dep/internal/test"
	"github.com/pkg/errors"
)

func TestStatusFormatVersion(t *testing.T) {
	t.Parallel()

	tests := map[gps.Version]string{
		nil: "",
		gps.NewBranch("master"):        "branch master",
		gps.NewVersion("1.0.0"):        "1.0.0",
		gps.Revision("flooboofoobooo"): "flooboo",
	}
	for version, expected := range tests {
		str := formatVersion(version)
		if str != expected {
			t.Fatalf("expected '%v', got '%v'", expected, str)
		}
	}
}

func TestBasicLine(t *testing.T) {
	project := dep.Project{}
	aSemverConstraint, _ := gps.NewSemverConstraint("1.2.3")

	templateString := "PR:{{.ProjectRoot}}, Const:{{.Constraint}}, Ver:{{.Version}}, Rev:{{.Revision}}, Lat:{{.Latest}}, PkgCt:{{.PackageCount}}"
	equalityTestTemplate := `{{if eq .Constraint "1.2.3"}}Constraint is 1.2.3{{end}}|{{if eq .Version "flooboo"}}Version is flooboo{{end}}|{{if eq .Latest "unknown"}}Latest is unknown{{end}}`

	tests := []struct {
		name                 string
		status               BasicStatus
		wantDotStatus        []string
		wantJSONStatus       []string
		wantTableStatus      []string
		wantTemplateStatus   []string
		wantEqTemplateStatus []string
	}{
		{
			name: "BasicStatus with ProjectRoot only",
			status: BasicStatus{
				ProjectRoot: "github.com/foo/bar",
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar"];`},
			wantJSONStatus:       []string{`"Version":""`, `"Revision":""`},
			wantTableStatus:      []string{`github.com/foo/bar                                         0`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Const:, Ver:, Rev:, Lat:, PkgCt:0`},
			wantEqTemplateStatus: []string{`||`},
		},
		{
			name: "BasicStatus with Revision",
			status: BasicStatus{
				ProjectRoot: "github.com/foo/bar",
				Revision:    gps.Revision("flooboofoobooo"),
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar\nflooboo"];`},
			wantJSONStatus:       []string{`"Version":""`, `"Revision":"flooboofoobooo"`, `"Constraint":""`},
			wantTableStatus:      []string{`github.com/foo/bar                       flooboo           0`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Const:, Ver:flooboo, Rev:flooboofoobooo, Lat:, PkgCt:0`},
			wantEqTemplateStatus: []string{`|Version is flooboo|`},
		},
		{
			name: "BasicStatus with Version and Revision",
			status: BasicStatus{
				ProjectRoot: "github.com/foo/bar",
				Version:     gps.NewVersion("1.0.0"),
				Revision:    gps.Revision("flooboofoobooo"),
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar\n1.0.0"];`},
			wantJSONStatus:       []string{`"Version":"1.0.0"`, `"Revision":"flooboofoobooo"`, `"Constraint":""`},
			wantTableStatus:      []string{`github.com/foo/bar              1.0.0    flooboo           0`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Const:, Ver:1.0.0, Rev:flooboofoobooo, Lat:, PkgCt:0`},
			wantEqTemplateStatus: []string{`||`},
		},
		{
			name: "BasicStatus with Constraint, Version and Revision",
			status: BasicStatus{
				ProjectRoot: "github.com/foo/bar",
				Constraint:  aSemverConstraint,
				Version:     gps.NewVersion("1.0.0"),
				Revision:    gps.Revision("revxyz"),
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar\n1.0.0"];`},
			wantJSONStatus:       []string{`"Revision":"revxyz"`, `"Constraint":"1.2.3"`, `"Version":"1.0.0"`},
			wantTableStatus:      []string{`github.com/foo/bar  1.2.3       1.0.0    revxyz            0`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Const:1.2.3, Ver:1.0.0, Rev:revxyz, Lat:, PkgCt:0`},
			wantEqTemplateStatus: []string{`Constraint is 1.2.3||`},
		},
		{
			name: "BasicStatus with update error",
			status: BasicStatus{
				ProjectRoot: "github.com/foo/bar",
				hasError:    true,
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar"];`},
			wantJSONStatus:       []string{`"Version":""`, `"Revision":""`, `"Latest":"unknown"`},
			wantTableStatus:      []string{`github.com/foo/bar                                 unknown  0`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Const:, Ver:, Rev:, Lat:unknown, PkgCt:0`},
			wantEqTemplateStatus: []string{`||Latest is unknown`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer

			dotout := &dotOutput{
				p: &project,
				w: &buf,
			}
			dotout.BasicHeader()
			dotout.BasicLine(&test.status)
			dotout.BasicFooter()

			for _, wantStatus := range test.wantDotStatus {
				if ok := strings.Contains(buf.String(), wantStatus); !ok {
					t.Errorf("Did not find expected node status: \n\t(GOT) %v \n\t(WNT) %v", buf.String(), wantStatus)
				}
			}

			buf.Reset()

			jsonout := &jsonOutput{w: &buf}

			jsonout.BasicHeader()
			jsonout.BasicLine(&test.status)
			jsonout.BasicFooter()

			for _, wantStatus := range test.wantJSONStatus {
				if ok := strings.Contains(buf.String(), wantStatus); !ok {
					t.Errorf("Did not find expected JSON status: \n\t(GOT) %v \n\t(WNT) %v", buf.String(), wantStatus)
				}
			}

			buf.Reset()

			tabw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)

			tableout := &tableOutput{w: tabw}

			tableout.BasicHeader()
			tableout.BasicLine(&test.status)
			tableout.BasicFooter()

			for _, wantStatus := range test.wantTableStatus {
				if ok := strings.Contains(buf.String(), wantStatus); !ok {
					t.Errorf("Did not find expected Table status: \n\t(GOT) %v \n\t(WNT) %v", buf.String(), wantStatus)
				}
			}

			buf.Reset()
			template, _ := template.New("status").Parse(templateString)
			templateout := &templateOutput{w: &buf, tmpl: template}
			templateout.BasicHeader()
			templateout.BasicLine(&test.status)
			templateout.BasicFooter()

			for _, wantStatus := range test.wantTemplateStatus {
				if ok := strings.Contains(buf.String(), wantStatus); !ok {
					t.Errorf("Did not find expected template status: \n\t(GOT) %v \n\t(WNT) %v", buf.String(), wantStatus)
				}
			}

			// The following test is to ensure that certain fields usable with string operations such as .eq
			buf.Reset()
			template, _ = template.New("status").Parse(equalityTestTemplate)
			templateout = &templateOutput{w: &buf, tmpl: template}
			templateout.BasicHeader()
			templateout.BasicLine(&test.status)
			templateout.BasicFooter()

			for _, wantStatus := range test.wantEqTemplateStatus {
				if ok := strings.Contains(buf.String(), wantStatus); !ok {
					t.Errorf("Did not find expected template status: \n\t(GOT) %v \n\t(WNT) %v", buf.String(), wantStatus)
				}
			}
		})
	}
}

func TestDetailLine(t *testing.T) {
	project := dep.Project{}
	aSemverConstraint, _ := gps.NewSemverConstraint("1.2.3")

	templateString := "{{range $p := .Projects}}PR:{{$p.ProjectRoot}}, Src:{{$p.Source}}, Const:{{$p.Constraint}}, Ver:{{$p.Locked.Version}}, Rev:{{$p.Locked.Revision}}, Lat:{{$p.Latest.Revision}}, PkgCt:{{$p.PackageCount}}, Pkgs:{{$p.Packages}}{{end}}"
	equalityTestTemplate := `{{range $p := .Projects}}{{if eq $p.Constraint "1.2.3"}}Constraint is 1.2.3{{end}}|{{if eq $p.Locked.Version "flooboo"}}Version is flooboo{{end}}|{{if eq $p.Locked.Revision "flooboofoobooo"}}Revision is flooboofoobooo{{end}}|{{if eq $p.Latest.Revision "unknown"}}Latest is unknown{{end}}{{end}}`

	tests := []struct {
		name                 string
		status               DetailStatus
		wantDotStatus        []string
		wantJSONStatus       []string
		wantTableStatus      []string
		wantTemplateStatus   []string
		wantEqTemplateStatus []string
	}{
		{
			name: "DetailStatus with ProjectRoot only",
			status: DetailStatus{
				BasicStatus: BasicStatus{
					ProjectRoot: "github.com/foo/bar",
				},
				Packages: []string{},
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar"];`},
			wantJSONStatus:       []string{`"Locked":{}`},
			wantTableStatus:      []string{`github.com/foo/bar                                                 []`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Src:, Const:, Ver:, Rev:, Lat:, PkgCt:0, Pkgs:[]`},
			wantEqTemplateStatus: []string{`||`},
		},
		{
			name: "DetailStatus with Revision",
			status: DetailStatus{
				BasicStatus: BasicStatus{
					ProjectRoot: "github.com/foo/bar",
					Revision:    gps.Revision("flooboofoobooo"),
				},
				Packages: []string{},
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar\nflooboo"];`},
			wantJSONStatus:       []string{`"Locked":{"Revision":"flooboofoobooo"}`, `"Constraint":""`},
			wantTableStatus:      []string{`github.com/foo/bar                               flooboo           []`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Src:, Const:, Ver:, Rev:flooboofoobooo, Lat:, PkgCt:0, Pkgs:[]`},
			wantEqTemplateStatus: []string{`|Revision is flooboofoobooo|`},
		},
		{
			name: "DetailStatus with Source",
			status: DetailStatus{
				BasicStatus: BasicStatus{
					ProjectRoot: "github.com/foo/bar",
				},
				Packages: []string{},
				Source:   "github.com/baz/bar",
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar"];`},
			wantJSONStatus:       []string{`"Locked":{}`, `"Source":"github.com/baz/bar"`, `"Constraint":""`},
			wantTableStatus:      []string{`github.com/foo/bar  github.com/baz/bar                                         []`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Src:github.com/baz/bar, Const:, Ver:, Rev:, Lat:, PkgCt:0, Pkgs:[]`},
			wantEqTemplateStatus: []string{`||`},
		},
		{
			name: "DetailStatus with Version and Revision",
			status: DetailStatus{
				BasicStatus: BasicStatus{
					ProjectRoot: "github.com/foo/bar",
					Version:     gps.NewVersion("1.0.0"),
					Revision:    gps.Revision("flooboofoobooo"),
				},
				Packages: []string{},
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar\n1.0.0"];`},
			wantJSONStatus:       []string{`"Version":"1.0.0"`, `"Revision":"flooboofoobooo"`, `"Constraint":""`},
			wantTableStatus:      []string{`github.com/foo/bar                      1.0.0    flooboo           []`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Src:, Const:, Ver:1.0.0, Rev:flooboofoobooo, Lat:, PkgCt:0, Pkgs:[]`},
			wantEqTemplateStatus: []string{`||`},
		},
		{
			name: "DetailStatus with Constraint, Version and Revision",
			status: DetailStatus{
				BasicStatus: BasicStatus{
					ProjectRoot: "github.com/foo/bar",
					Constraint:  aSemverConstraint,
					Version:     gps.NewVersion("1.0.0"),
					Revision:    gps.Revision("revxyz"),
				},
				Packages: []string{},
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar\n1.0.0"];`},
			wantJSONStatus:       []string{`"Revision":"revxyz"`, `"Constraint":"1.2.3"`, `"Version":"1.0.0"`},
			wantTableStatus:      []string{`github.com/foo/bar          1.2.3       1.0.0    revxyz            []`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Src:, Const:1.2.3, Ver:1.0.0, Rev:revxyz, Lat:, PkgCt:0, Pkgs:[]`},
			wantEqTemplateStatus: []string{`Constraint is 1.2.3||`},
		},
		{
			name: "DetailStatus with Constraint, Version, Revision, and Package",
			status: DetailStatus{
				BasicStatus: BasicStatus{
					ProjectRoot:  "github.com/foo/bar",
					Constraint:   aSemverConstraint,
					Version:      gps.NewVersion("1.0.0"),
					Revision:     gps.Revision("revxyz"),
					PackageCount: 1,
				},
				Packages: []string{"."},
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar\n1.0.0"];`},
			wantJSONStatus:       []string{`"Revision":"revxyz"`, `"Constraint":"1.2.3"`, `"Version":"1.0.0"`, `"PackageCount":1`, `"Packages":["."]`},
			wantTableStatus:      []string{`github.com/foo/bar          1.2.3       1.0.0    revxyz            [.]`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Src:, Const:1.2.3, Ver:1.0.0, Rev:revxyz, Lat:, PkgCt:1, Pkgs:[.]`},
			wantEqTemplateStatus: []string{`Constraint is 1.2.3||`},
		},
		{
			name: "DetailStatus with Constraint, Version, Revision, and Packages",
			status: DetailStatus{
				BasicStatus: BasicStatus{
					ProjectRoot:  "github.com/foo/bar",
					Constraint:   aSemverConstraint,
					Version:      gps.NewVersion("1.0.0"),
					Revision:     gps.Revision("revxyz"),
					PackageCount: 3,
				},
				Packages: []string{".", "foo", "bar"},
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar\n1.0.0"];`},
			wantJSONStatus:       []string{`"Revision":"revxyz"`, `"Constraint":"1.2.3"`, `"Version":"1.0.0"`, `"PackageCount":3`, `"Packages":[".","foo","bar"]`},
			wantTableStatus:      []string{`github.com/foo/bar          1.2.3       1.0.0    revxyz            [., foo, bar]`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Src:, Const:1.2.3, Ver:1.0.0, Rev:revxyz, Lat:, PkgCt:3, Pkgs:[. foo bar]`},
			wantEqTemplateStatus: []string{`Constraint is 1.2.3||`},
		},
		{
			name: "DetailStatus with update error",
			status: DetailStatus{
				BasicStatus: BasicStatus{
					ProjectRoot: "github.com/foo/bar",
					hasError:    true,
				},
				Packages: []string{},
			},
			wantDotStatus:        []string{`[label="github.com/foo/bar"];`},
			wantJSONStatus:       []string{`"Locked":{}`, `"Latest":{"Revision":"unknown"}`},
			wantTableStatus:      []string{`github.com/foo/bar                                         unknown  []`},
			wantTemplateStatus:   []string{`PR:github.com/foo/bar, Src:, Const:, Ver:, Rev:, Lat:unknown, PkgCt:0, Pkgs:[]`},
			wantEqTemplateStatus: []string{`||Latest is unknown`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer

			dotout := &dotOutput{
				p: &project,
				w: &buf,
			}
			dotout.DetailHeader(nil)
			dotout.DetailLine(&test.status)
			dotout.DetailFooter(nil)

			for _, wantStatus := range test.wantDotStatus {
				if ok := strings.Contains(buf.String(), wantStatus); !ok {
					t.Errorf("Did not find expected node status: \n\t(GOT) %v \n\t(WNT) %v", buf.String(), wantStatus)
				}
			}

			buf.Reset()

			jsonout := &jsonOutput{w: &buf}

			jsonout.DetailHeader(nil)
			jsonout.DetailLine(&test.status)
			jsonout.DetailFooter(nil)

			for _, wantStatus := range test.wantJSONStatus {
				if ok := strings.Contains(buf.String(), wantStatus); !ok {
					t.Errorf("Did not find expected JSON status: \n\t(GOT) %v \n\t(WNT) %v", buf.String(), wantStatus)
				}
			}

			buf.Reset()

			tabw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)

			tableout := &tableOutput{w: tabw}

			tableout.DetailHeader(nil)
			tableout.DetailLine(&test.status)
			tableout.DetailFooter(nil)

			for _, wantStatus := range test.wantTableStatus {
				if ok := strings.Contains(buf.String(), wantStatus); !ok {
					t.Errorf("Did not find expected Table status: \n\t(GOT) %v \n\t(WNT) %v", buf.String(), wantStatus)
				}
			}

			buf.Reset()
			template, _ := template.New("status").Parse(templateString)
			templateout := &templateOutput{w: &buf, tmpl: template}
			templateout.DetailHeader(nil)
			templateout.DetailLine(&test.status)
			templateout.DetailFooter(nil)

			for _, wantStatus := range test.wantTemplateStatus {
				if ok := strings.Contains(buf.String(), wantStatus); !ok {
					t.Errorf("Did not find expected template status: \n\t(GOT) %v \n\t(WNT) %v", buf.String(), wantStatus)
				}
			}

			// The following test is to ensure that certain fields usable with string operations such as .eq
			buf.Reset()
			template, _ = template.New("status").Parse(equalityTestTemplate)
			templateout = &templateOutput{w: &buf, tmpl: template}
			templateout.DetailHeader(nil)
			templateout.DetailLine(&test.status)
			templateout.DetailFooter(nil)

			for _, wantStatus := range test.wantEqTemplateStatus {
				if ok := strings.Contains(buf.String(), wantStatus); !ok {
					t.Errorf("Did not find expected template status: \n\t(GOT) %v \n\t(WNT) %v", buf.String(), wantStatus)
				}
			}
		})
	}
}

func TestBasicStatusGetConsolidatedConstraint(t *testing.T) {
	aSemverConstraint, _ := gps.NewSemverConstraint("1.2.1")

	testCases := []struct {
		name           string
		basicStatus    BasicStatus
		wantConstraint string
	}{
		{
			name:           "empty BasicStatus",
			basicStatus:    BasicStatus{},
			wantConstraint: "",
		},
		{
			name: "BasicStatus with Any Constraint",
			basicStatus: BasicStatus{
				Constraint: gps.Any(),
			},
			wantConstraint: "*",
		},
		{
			name: "BasicStatus with Semver Constraint",
			basicStatus: BasicStatus{
				Constraint: aSemverConstraint,
			},
			wantConstraint: "1.2.1",
		},
		{
			name: "BasicStatus with Override",
			basicStatus: BasicStatus{
				Constraint:  aSemverConstraint,
				hasOverride: true,
			},
			wantConstraint: "1.2.1 (override)",
		},
		{
			name: "BasicStatus with Revision Constraint",
			basicStatus: BasicStatus{
				Constraint: gps.Revision("ddeb6f5d27091ff291b16232e99076a64fb375b8"),
			},
			wantConstraint: "ddeb6f5",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.basicStatus.getConsolidatedConstraint() != tc.wantConstraint {
				t.Errorf("unexpected consolidated constraint: \n\t(GOT) %v \n\t(WNT) %v", tc.basicStatus.getConsolidatedConstraint(), tc.wantConstraint)
			}
		})
	}
}

func TestBasicStatusGetConsolidatedVersion(t *testing.T) {
	testCases := []struct {
		name        string
		basicStatus BasicStatus
		wantVersion string
	}{
		{
			name:        "empty BasicStatus",
			basicStatus: BasicStatus{},
			wantVersion: "",
		},
		{
			name: "BasicStatus with Version and Revision",
			basicStatus: BasicStatus{
				Version:  gps.NewVersion("1.0.0"),
				Revision: gps.Revision("revxyz"),
			},
			wantVersion: "1.0.0",
		},
		{
			name: "BasicStatus with only Revision",
			basicStatus: BasicStatus{
				Revision: gps.Revision("revxyz"),
			},
			wantVersion: "revxyz",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.basicStatus.getConsolidatedVersion() != tc.wantVersion {
				t.Errorf("unexpected consolidated version: \n\t(GOT) %v \n\t(WNT) %v", tc.basicStatus.getConsolidatedVersion(), tc.wantVersion)
			}
		})
	}
}

func TestBasicStatusGetConsolidatedLatest(t *testing.T) {
	testCases := []struct {
		name        string
		basicStatus BasicStatus
		revSize     uint8
		wantLatest  string
	}{
		{
			name:        "empty BasicStatus",
			basicStatus: BasicStatus{},
			revSize:     shortRev,
			wantLatest:  "",
		},
		{
			name: "nil latest",
			basicStatus: BasicStatus{
				Latest: nil,
			},
			revSize:    shortRev,
			wantLatest: "",
		},
		{
			name: "with error",
			basicStatus: BasicStatus{
				hasError: true,
			},
			revSize:    shortRev,
			wantLatest: "unknown",
		},
		{
			name: "short latest",
			basicStatus: BasicStatus{
				Latest: gps.Revision("adummylonglongrevision"),
			},
			revSize:    shortRev,
			wantLatest: "adummyl",
		},
		{
			name: "long latest",
			basicStatus: BasicStatus{
				Latest: gps.Revision("adummylonglongrevision"),
			},
			revSize:    longRev,
			wantLatest: "adummylonglongrevision",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotRev := tc.basicStatus.getConsolidatedLatest(tc.revSize)
			if gotRev != tc.wantLatest {
				t.Errorf("unexpected consolidated latest: \n\t(GOT) %v \n\t(WNT) %v", gotRev, tc.wantLatest)
			}
		})
	}
}

func TestCollectConstraints(t *testing.T) {
	ver1, _ := gps.NewSemverConstraintIC("v1.0.0")
	ver08, _ := gps.NewSemverConstraintIC("v0.8.0")
	ver2, _ := gps.NewSemverConstraintIC("v2.0.0")

	cases := []struct {
		name            string
		lock            dep.Lock
		manifest        dep.Manifest
		wantConstraints constraintsCollection
		wantErr         bool
	}{
		{
			name: "without any constraints",
			lock: dep.Lock{
				P: []gps.LockedProject{
					gps.NewLockedProject(
						gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/sdboyer/deptest")},
						gps.NewVersion("v1.0.0"),
						[]string{"."},
					),
				},
			},
			wantConstraints: constraintsCollection{},
		},
		{
			name: "with multiple constraints from dependencies",
			lock: dep.Lock{
				P: []gps.LockedProject{
					gps.NewLockedProject(
						gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/sdboyer/deptest")},
						gps.NewVersion("v1.0.0"),
						[]string{"."},
					),
					gps.NewLockedProject(
						gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/darkowlzz/deptest-project-1")},
						gps.NewVersion("v0.1.0"),
						[]string{"."},
					),
					gps.NewLockedProject(
						gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/darkowlzz/deptest-project-2")},
						gps.NewBranch("master").Pair(gps.Revision("824a8d56a4c6b2f4718824a98cd6d70d3dbd4c3e")),
						[]string{"."},
					),
				},
			},
			wantConstraints: constraintsCollection{
				"github.com/sdboyer/deptestdos": []projectConstraint{
					{"github.com/darkowlzz/deptest-project-2", ver2},
				},
				"github.com/sdboyer/dep-test": []projectConstraint{
					{"github.com/darkowlzz/deptest-project-2", ver1},
				},
				"github.com/sdboyer/deptest": []projectConstraint{
					{"github.com/darkowlzz/deptest-project-1", ver1},
					{"github.com/darkowlzz/deptest-project-2", ver08},
				},
			},
		},
		{
			name: "with multiple constraints from dependencies and root project",
			lock: dep.Lock{
				P: []gps.LockedProject{
					gps.NewLockedProject(
						gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/sdboyer/deptest")},
						gps.NewVersion("v1.0.0"),
						[]string{"."},
					),
					gps.NewLockedProject(
						gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/darkowlzz/deptest-project-1")},
						gps.NewVersion("v0.1.0"),
						[]string{"."},
					),
					gps.NewLockedProject(
						gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/darkowlzz/deptest-project-2")},
						gps.NewBranch("master").Pair(gps.Revision("824a8d56a4c6b2f4718824a98cd6d70d3dbd4c3e")),
						[]string{"."},
					),
				},
			},
			manifest: dep.Manifest{
				Constraints: map[gps.ProjectRoot]gps.ProjectProperties{
					gps.ProjectRoot("github.com/sdboyer/deptest"): {
						Constraint: gps.Revision("3f4c3bea144e112a69bbe5d8d01c1b09a544253f"),
					},
				},
				Ovr: make(gps.ProjectConstraints),
				PruneOptions: gps.CascadingPruneOptions{
					DefaultOptions:    gps.PruneNestedVendorDirs,
					PerProjectOptions: make(map[gps.ProjectRoot]gps.PruneOptionSet),
				},
			},
			wantConstraints: constraintsCollection{
				"github.com/sdboyer/deptestdos": []projectConstraint{
					{"github.com/darkowlzz/deptest-project-2", ver2},
				},
				"github.com/sdboyer/dep-test": []projectConstraint{
					{"github.com/darkowlzz/deptest-project-2", ver1},
				},
				"github.com/sdboyer/deptest": []projectConstraint{
					{"github.com/darkowlzz/deptest-project-1", ver1},
					{"github.com/darkowlzz/deptest-project-2", ver08},
					{"root", gps.Revision("3f4c3bea144e112a69bbe5d8d01c1b09a544253f")},
				},
			},
		},
		{
			name: "skip projects with invalid versions",
			lock: dep.Lock{
				P: []gps.LockedProject{
					gps.NewLockedProject(
						gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/darkowlzz/deptest-project-1")},
						gps.NewVersion("v0.1.0"),
						[]string{"."},
					),
					gps.NewLockedProject(
						gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/darkowlzz/deptest-project-2")},
						gps.NewVersion("v1.0.0"),
						[]string{"."},
					),
				},
			},
			wantConstraints: constraintsCollection{
				"github.com/sdboyer/deptest": []projectConstraint{
					{"github.com/darkowlzz/deptest-project-1", ver1},
				},
			},
			wantErr: true,
		},
		{
			name: "collect only applicable constraints",
			lock: dep.Lock{
				P: []gps.LockedProject{
					gps.NewLockedProject(
						gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/darkowlzz/dep-applicable-constraints")},
						gps.NewVersion("v1.0.0"),
						[]string{"."},
					),
				},
			},
			wantConstraints: constraintsCollection{
				"github.com/boltdb/bolt": []projectConstraint{
					{"github.com/darkowlzz/dep-applicable-constraints", gps.NewBranch("master")},
				},
				"github.com/sdboyer/deptest": []projectConstraint{
					{"github.com/darkowlzz/dep-applicable-constraints", ver08},
				},
			},
		},
		{
			name: "skip ineffective constraint from manifest",
			lock: dep.Lock{
				P: []gps.LockedProject{
					gps.NewLockedProject(
						gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot("github.com/sdboyer/deptest")},
						gps.NewVersion("v1.0.0"),
						[]string{"."},
					),
				},
			},
			manifest: dep.Manifest{
				Constraints: map[gps.ProjectRoot]gps.ProjectProperties{
					gps.ProjectRoot("github.com/darkowlzz/deptest-project-1"): {
						Constraint: ver1,
					},
				},
				Ovr: make(gps.ProjectConstraints),
				PruneOptions: gps.CascadingPruneOptions{
					DefaultOptions:    gps.PruneNestedVendorDirs,
					PerProjectOptions: make(map[gps.ProjectRoot]gps.PruneOptionSet),
				},
			},
			wantConstraints: constraintsCollection{},
		},
	}

	h := test.NewHelper(t)
	defer h.Cleanup()

	testdir := filepath.Join("src", "collect_constraints_test")
	h.TempDir(testdir)
	h.TempCopy(filepath.Join(testdir, "main.go"), filepath.Join("status", "collect_constraints", "main.go"))
	testProjPath := h.Path(testdir)

	discardLogger := log.New(ioutil.Discard, "", 0)

	ctx := &dep.Ctx{
		GOPATH: testProjPath,
		Out:    discardLogger,
		Err:    discardLogger,
	}

	sm, err := ctx.SourceManager()
	h.Must(err)
	defer sm.Release()

	// Create new project and set root. Setting root is required for PackageList
	// to run properly.
	p := new(dep.Project)
	p.SetRoot(testProjPath)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p.Lock = &c.lock
			p.Manifest = &c.manifest
			gotConstraints, err := collectConstraints(ctx, p, sm)
			if len(err) > 0 && !c.wantErr {
				t.Fatalf("unexpected errors while collecting constraints: %v", err)
			} else if len(err) == 0 && c.wantErr {
				t.Fatalf("expected errors while collecting constraints, but got none")
			}

			if !reflect.DeepEqual(gotConstraints, c.wantConstraints) {
				t.Fatalf("unexpected collected constraints: \n\t(GOT): %v\n\t(WNT): %v", gotConstraints, c.wantConstraints)
			}
		})
	}
}

func TestValidateFlags(t *testing.T) {
	testCases := []struct {
		name    string
		cmd     statusCommand
		wantErr error
	}{
		{
			name:    "no flags",
			cmd:     statusCommand{},
			wantErr: nil,
		},
		{
			name:    "-dot only",
			cmd:     statusCommand{dot: true},
			wantErr: nil,
		},
		{
			name:    "-dot with template",
			cmd:     statusCommand{dot: true, template: "foo"},
			wantErr: errors.New("cannot pass template string with -dot"),
		},
		{
			name:    "-dot with -json",
			cmd:     statusCommand{dot: true, json: true},
			wantErr: errors.New("cannot pass multiple output format flags"),
		},
		{
			name:    "-dot with operating mode",
			cmd:     statusCommand{dot: true, old: true},
			wantErr: errors.New("-dot generates dependency graph; cannot pass other flags"),
		},
		{
			name:    "single operating mode",
			cmd:     statusCommand{old: true},
			wantErr: nil,
		},
		{
			name:    "multiple operating modes",
			cmd:     statusCommand{missing: true, old: true},
			wantErr: errors.Wrapf(errors.New("cannot pass multiple operating mode flags"), "[-old -missing]"),
		},
		{
			name:    "old with -dot",
			cmd:     statusCommand{dot: true, old: true},
			wantErr: errors.New("-dot generates dependency graph; cannot pass other flags"),
		},
		{
			name:    "old with template",
			cmd:     statusCommand{old: true, template: "foo"},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cmd.validateFlags()

			if err == nil {
				if tc.wantErr != nil {
					t.Errorf("unexpected error: \n\t(GOT): %v\n\t(WNT): %v", err, tc.wantErr)
				}
			} else if err.Error() != tc.wantErr.Error() {
				t.Errorf("unexpected error: \n\t(GOT): %v\n\t(WNT): %v", err, tc.wantErr)
			}
		})
	}
}

func execStatusTemplate(w io.Writer, format string, data interface{}) error {
	tpl, err := parseStatusTemplate(format)
	if err != nil {
		return err
	}
	return tpl.Execute(w, data)
}

const expectedStatusDetail = `# This file is autogenerated, do not edit; changes may be undone by the next 'dep ensure'.


%s[solve-meta]
  analyzer-name = "dep"
  analyzer-version = 1
  input-imports = %s
  solver-name = "gps-cdcl"
  solver-version = 1
`

func TestStatusDetailTemplates(t *testing.T) {
	expectedStatusMetadata := rawDetailMetadata{
		AnalyzerName:    "dep",
		AnalyzerVersion: 1,
		SolverName:      "gps-cdcl",
		SolverVersion:   1,
	}
	expectWithInputs := expectedStatusMetadata
	expectWithInputs.InputImports = []string{"github.com/akutz/one", "github.com/akutz/three/a"}

	testCases := []struct {
		name string
		tpl  string
		exp  string
		data rawDetail
	}{
		{
			name: "Lock Template No Projects",
			tpl:  statusLockTemplate,
			exp:  fmt.Sprintf(expectedStatusDetail, "", tomlStrSplit(nil)),
			data: rawDetail{
				Metadata: expectedStatusMetadata,
			},
		},
		{
			name: "Lock Template",
			tpl:  statusLockTemplate,
			exp: fmt.Sprintf(expectedStatusDetail, `[[projects]]
  branch = "master"
  digest = "1:cbcdef1234"
  name = "github.com/akutz/one"
  packages = ["."]
  pruneopts = "UT"
  revision = "b78744579491c1ceeaaa3b40205e56b0591b93a3"

[[projects]]
  digest = "1:dbcdef1234"
  name = "github.com/akutz/two"
  packages = [
    ".",
    "helloworld",
  ]
  pruneopts = "NUT"
  revision = "12bd96e66386c1960ab0f74ced1362f66f552f7b"
  version = "v1.0.0"

[[projects]]
  branch = "feature/morning"
  digest = "1:abcdef1234"
  name = "github.com/akutz/three"
  packages = [
    "a",
    "b",
    "c",
  ]
  pruneopts = "NUT"
  revision = "890a5c3458b43e6104ff5da8dfa139d013d77544"
  source = "https://github.com/mandy/three"

`, tomlStrSplit([]string{"github.com/akutz/one", "github.com/akutz/three/a"})),
			data: rawDetail{
				Projects: []rawDetailProject{
					rawDetailProject{
						Locked: rawDetailVersion{
							Branch:   "master",
							Revision: "b78744579491c1ceeaaa3b40205e56b0591b93a3",
						},
						Packages:    []string{"."},
						ProjectRoot: "github.com/akutz/one",
						PruneOpts:   "UT",
						Digest:      "1:cbcdef1234",
					},
					rawDetailProject{
						Locked: rawDetailVersion{
							Revision: "12bd96e66386c1960ab0f74ced1362f66f552f7b",
							Version:  "v1.0.0",
						},
						ProjectRoot: "github.com/akutz/two",
						Packages: []string{
							".",
							"helloworld",
						},
						PruneOpts: "NUT",
						Digest:    "1:dbcdef1234",
					},
					rawDetailProject{
						Locked: rawDetailVersion{
							Branch:   "feature/morning",
							Revision: "890a5c3458b43e6104ff5da8dfa139d013d77544",
						},
						ProjectRoot: "github.com/akutz/three",
						Packages: []string{
							"a",
							"b",
							"c",
						},
						Source:    "https://github.com/mandy/three",
						PruneOpts: "NUT",
						Digest:    "1:abcdef1234",
					},
				},
				Metadata: expectWithInputs,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			if err := execStatusTemplate(w, tc.tpl, tc.data); err != nil {
				t.Error(err)
			}
			act := w.String()
			if act != tc.exp {
				t.Errorf(
					"unexpected error: \n"+
						"(GOT):\n=== BEGIN ===\n%v\n=== END ===\n"+
						"(WNT):\n=== BEGIN ===\n%v\n=== END ===\n",
					act,
					tc.exp)
			}
		})
	}
}
