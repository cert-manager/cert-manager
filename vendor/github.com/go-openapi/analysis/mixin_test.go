// Copyright 2015 go-swagger maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analysis

import (
	"testing"
)

const (
	widgetFile     = "fixtures/widget-crud.yml"
	fooFile        = "fixtures/foo-crud.yml"
	barFile        = "fixtures/bar-crud.yml"
	noPathsFile    = "fixtures/no-paths.yml"
	emptyPathsFile = "fixtures/empty-paths.json"
	securityFile   = "fixtures/securitydef.yml"
	otherMixin     = "fixtures/other-mixin.yml"
)

func TestMixin(t *testing.T) {

	primary, err := loadSpec(widgetFile)
	if err != nil {
		t.Fatalf("Could not load '%v': %v\n", widgetFile, err)
	}
	mixin1, err := loadSpec(fooFile)
	if err != nil {
		t.Fatalf("Could not load '%v': %v\n", fooFile, err)
	}
	mixin2, err := loadSpec(barFile)
	if err != nil {
		t.Fatalf("Could not load '%v': %v\n", barFile, err)
	}
	mixin3, err := loadSpec(noPathsFile)
	if err != nil {
		t.Fatalf("Could not load '%v': %v\n", noPathsFile, err)
	}
	mixin4, err := loadSpec(securityFile)
	if err != nil {
		t.Fatalf("Could not load '%v': %v\n", securityFile, err)
	}

	mixin5, err := loadSpec(otherMixin)
	if err != nil {
		t.Fatalf("Could not load '%v': %v\n", otherMixin, err)
	}

	collisions := Mixin(primary, mixin1, mixin2, mixin3, mixin4, mixin5)
	if len(collisions) != 19 {
		t.Errorf("TestMixin: Expected 19 collisions, got %v\n%v", len(collisions), collisions)
	}

	if len(primary.Paths.Paths) != 7 {
		t.Errorf("TestMixin: Expected 7 paths in merged, got %v\n", len(primary.Paths.Paths))
	}

	if len(primary.Definitions) != 8 {
		t.Errorf("TestMixin: Expected 8 definitions in merged, got %v\n", len(primary.Definitions))
	}

	if len(primary.Parameters) != 4 {
		t.Errorf("TestMixin: Expected 4 top level parameters in merged, got %v\n", len(primary.Parameters))
	}

	if len(primary.Responses) != 2 {
		t.Errorf("TestMixin: Expected 2 top level responses in merged, got %v\n", len(primary.Responses))
	}

	if len(primary.SecurityDefinitions) != 5 {
		t.Errorf("TestMixin: Expected 5 top level SecurityDefinitions in merged, got %v\n", len(primary.SecurityDefinitions))
	}

	if len(primary.Security) != 3 {
		t.Errorf("TestMixin: Expected 3 top level Security requirements in merged, got %v\n", len(primary.Security))
	}

	if len(primary.Tags) != 3 {
		t.Errorf("TestMixin: Expected 3 top level tags merged, got %v\n", len(primary.Security))
	}

	if len(primary.Schemes) != 2 {
		t.Errorf("TestMixin: Expected 2 top level schemes merged, got %v\n", len(primary.Security))
	}

	if len(primary.Consumes) != 2 {
		t.Errorf("TestMixin: Expected 2 top level Consumers merged, got %v\n", len(primary.Security))
	}

	if len(primary.Produces) != 2 {
		t.Errorf("TestMixin: Expected 2 top level Producers merged, got %v\n", len(primary.Security))
	}

	// test that adding paths to a primary with no paths works (was NPE)
	emptyPaths, err := loadSpec(emptyPathsFile)
	if err != nil {
		t.Fatalf("Could not load '%v': %v\n", emptyPathsFile, err)
	}

	collisions = Mixin(emptyPaths, primary)
	if len(collisions) != 0 {
		t.Errorf("TestMixin: Expected 0 collisions, got %v\n%v", len(collisions), collisions)
	}
	//bbb, _ := json.MarshalIndent(primary, "", " ")
	//t.Log(string(bbb))
}

func TestMixinFromNilPath(t *testing.T) {
	primary, err := loadSpec(otherMixin)
	if err != nil {
		t.Fatalf("Could not load '%v': %v\n", otherMixin, err)
	}
	mixin1, err := loadSpec(widgetFile)
	if err != nil {
		t.Fatalf("Could not load '%v': %v\n", widgetFile, err)
	}
	collisions := Mixin(primary, mixin1)
	if len(collisions) != 1 {
		t.Errorf("TestMixin: Expected 1 collisions, got %v\n%v", len(collisions), collisions)
	}
	if len(primary.Paths.Paths) != 3 {
		t.Errorf("TestMixin: Expected 3 paths in merged, got %v\n", len(primary.Paths.Paths))
	}
	//bbb, _ := json.MarshalIndent(primary.Paths.Paths, "", " ")
	//t.Log(string(bbb))
}
