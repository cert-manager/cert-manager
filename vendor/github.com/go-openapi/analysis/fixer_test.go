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
	"path/filepath"
	"strconv"
	"testing"

	"github.com/go-openapi/spec"
	"github.com/stretchr/testify/assert"
)

func Test_FixEmptyResponseDescriptions(t *testing.T) {
	bp := filepath.Join("fixtures", "fixer", "fixer.yaml")
	sp := loadOrFail(t, bp)
	FixEmptyResponseDescriptions(sp)

	for path, pathItem := range sp.Paths.Paths {
		if !assert.NotNil(t, pathItem, "expected a fixture with all path items provided in: %s", path) {
			continue
		}

		if path == "/noDesc" {
			// scope for fixed descriptions
			assertAllVerbs(t, pathItem, true)
		} else {
			// scope for unchanged descriptions
			assertAllVerbs(t, pathItem, false)
		}
	}
	for r, resp := range sp.Responses {
		assert.Truef(t, assertResponse(t, "/responses/"+r, &resp, true),
			"expected a fixed empty description in response %s", r)
	}
}

func assertAllVerbs(t *testing.T, pathItem spec.PathItem, isEmpty bool) {
	msg := "expected %s description for %s"
	var mode string
	if isEmpty {
		mode = "a fixed empty"
	} else {
		mode = "an unmodified"
	}
	assert.Truef(t, assertResponseInOperation(t, pathItem.Get, isEmpty), msg, mode, "GET")
	assert.Truef(t, assertResponseInOperation(t, pathItem.Put, isEmpty), msg, mode, "PUT")
	assert.Truef(t, assertResponseInOperation(t, pathItem.Post, isEmpty), msg, mode, "POST")
	assert.Truef(t, assertResponseInOperation(t, pathItem.Delete, isEmpty), msg, mode, "DELETE")
	assert.Truef(t, assertResponseInOperation(t, pathItem.Options, isEmpty), msg, mode, "OPTIONS")
	assert.Truef(t, assertResponseInOperation(t, pathItem.Patch, isEmpty), msg, mode, "PATCH")
	assert.Truef(t, assertResponseInOperation(t, pathItem.Head, isEmpty), msg, mode, "HEAD")
}

func assertResponseInOperation(t *testing.T, op *spec.Operation, isEmpty bool) (result bool) {
	result = true
	if op == nil {
		t.Fatalf("expected a fixture with all REST verbs set")
	}
	if op.Responses != nil {
		if op.Responses.Default != nil {
			assert.Truef(t, assertResponse(t, "default", op.Responses.Default, isEmpty),
				"unexpected description in response %s for operation", "default")
		}
		for code, resp := range op.Responses.StatusCodeResponses {
			assert.Truef(t, assertResponse(t, strconv.Itoa(code), &resp, isEmpty),
				"unexpected description in response %d for operation", code)
		}
	}
	return
}
func assertResponse(t *testing.T, path string, resp *spec.Response, isEmpty bool) bool {
	var expected string
	if isEmpty {
		expected = "(empty)"
	} else {
		expected = "my description"
	}
	if resp.Ref.String() != "" {
		expected = ""
	}
	if !assert.Equalf(t, expected, resp.Description, "unexpected description for resp. %s", path) {
		return false
	}
	return true
}
