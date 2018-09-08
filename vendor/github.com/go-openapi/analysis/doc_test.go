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

package analysis_test

import (
	"fmt"

	"github.com/go-openapi/analysis" // This package
	"github.com/go-openapi/loads"    // Spec loading
)

func ExampleSpec() {
	// Example with spec file in this repo
	path := "fixtures/flatten.yml"
	doc, err := loads.Spec(path) // Load spec from file
	if err == nil {
		an := analysis.New(doc.Spec()) // Analyze spec

		paths := an.AllPaths()
		fmt.Printf("This spec contains %d paths", len(paths))
	}
	// Output: This spec contains 2 paths
}

func ExampleFlatten() {
	// Example with spec file in this repo
	path := "fixtures/flatten.yml"
	doc, err := loads.Spec(path) // Load spec from file
	if err == nil {
		an := analysis.New(doc.Spec()) // Analyze spec
		// flatten the specification in doc
		erf := analysis.Flatten(analysis.FlattenOpts{Spec: an, BasePath: path})
		if erf == nil {
			fmt.Printf("Specification doc flattened")
		}
		// .. the analyzed spec has been updated and may be now used with the reworked spec
	}
	// Output: Specification doc flattened
}
