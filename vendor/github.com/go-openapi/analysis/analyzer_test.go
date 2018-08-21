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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/go-openapi/loads/fmts"
	"github.com/go-openapi/spec"
	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/assert"
)

func schemeNames(schemes [][]SecurityRequirement) []string {
	var names []string
	for _, scheme := range schemes {
		for _, v := range scheme {
			names = append(names, v.Name)
		}
	}
	sort.Strings(names)
	return names
}

func makeFixturepec(pi, pi2 spec.PathItem, formatParam *spec.Parameter) *spec.Swagger {
	return &spec.Swagger{
		SwaggerProps: spec.SwaggerProps{
			Consumes: []string{"application/json"},
			Produces: []string{"application/json"},
			Security: []map[string][]string{
				{"apikey": nil},
			},
			SecurityDefinitions: map[string]*spec.SecurityScheme{
				"basic":  spec.BasicAuth(),
				"apiKey": spec.APIKeyAuth("api_key", "query"),
				"oauth2": spec.OAuth2AccessToken("http://authorize.com", "http://token.com"),
			},
			Parameters: map[string]spec.Parameter{"format": *formatParam},
			Paths: &spec.Paths{
				Paths: map[string]spec.PathItem{
					"/":      pi,
					"/items": pi2,
				},
			},
		},
	}
}

func TestAnalyzer(t *testing.T) {
	formatParam := spec.QueryParam("format").Typed("string", "")

	limitParam := spec.QueryParam("limit").Typed("integer", "int32")
	limitParam.Extensions = spec.Extensions(map[string]interface{}{})
	limitParam.Extensions.Add("go-name", "Limit")

	skipParam := spec.QueryParam("skip").Typed("integer", "int32")
	pi := spec.PathItem{}
	pi.Parameters = []spec.Parameter{*limitParam}

	op := &spec.Operation{}
	op.Consumes = []string{"application/x-yaml"}
	op.Produces = []string{"application/x-yaml"}
	op.Security = []map[string][]string{
		{"oauth2": {}},
		{"basic": nil},
	}
	op.ID = "someOperation"
	op.Parameters = []spec.Parameter{*skipParam}
	pi.Get = op

	pi2 := spec.PathItem{}
	pi2.Parameters = []spec.Parameter{*limitParam}
	op2 := &spec.Operation{}
	op2.ID = "anotherOperation"
	op2.Parameters = []spec.Parameter{*skipParam}
	pi2.Get = op2

	spec := makeFixturepec(pi, pi2, formatParam)
	analyzer := New(spec)

	assert.Len(t, analyzer.consumes, 2)
	assert.Len(t, analyzer.produces, 2)
	assert.Len(t, analyzer.operations, 1)
	assert.Equal(t, analyzer.operations["GET"]["/"], spec.Paths.Paths["/"].Get)

	expected := []string{"application/x-yaml"}
	sort.Strings(expected)
	consumes := analyzer.ConsumesFor(spec.Paths.Paths["/"].Get)
	sort.Strings(consumes)
	assert.Equal(t, expected, consumes)

	produces := analyzer.ProducesFor(spec.Paths.Paths["/"].Get)
	sort.Strings(produces)
	assert.Equal(t, expected, produces)

	expected = []string{"application/json"}
	sort.Strings(expected)
	consumes = analyzer.ConsumesFor(spec.Paths.Paths["/items"].Get)
	sort.Strings(consumes)
	assert.Equal(t, expected, consumes)

	produces = analyzer.ProducesFor(spec.Paths.Paths["/items"].Get)
	sort.Strings(produces)
	assert.Equal(t, expected, produces)

	expectedSchemes := [][]SecurityRequirement{
		{
			{Name: "oauth2", Scopes: []string{}},
			{Name: "basic", Scopes: nil},
		},
	}
	schemes := analyzer.SecurityRequirementsFor(spec.Paths.Paths["/"].Get)
	assert.Equal(t, schemeNames(expectedSchemes), schemeNames(schemes))

	securityDefinitions := analyzer.SecurityDefinitionsFor(spec.Paths.Paths["/"].Get)
	assert.Equal(t, *spec.SecurityDefinitions["basic"], securityDefinitions["basic"])
	assert.Equal(t, *spec.SecurityDefinitions["oauth2"], securityDefinitions["oauth2"])

	parameters := analyzer.ParamsFor("GET", "/")
	assert.Len(t, parameters, 2)

	operations := analyzer.OperationIDs()
	assert.Len(t, operations, 2)

	producers := analyzer.RequiredProduces()
	assert.Len(t, producers, 2)
	consumers := analyzer.RequiredConsumes()
	assert.Len(t, consumers, 2)
	authSchemes := analyzer.RequiredSecuritySchemes()
	assert.Len(t, authSchemes, 3)

	ops := analyzer.Operations()
	assert.Len(t, ops, 1)
	assert.Len(t, ops["GET"], 2)

	op, ok := analyzer.OperationFor("get", "/")
	assert.True(t, ok)
	assert.NotNil(t, op)

	op, ok = analyzer.OperationFor("delete", "/")
	assert.False(t, ok)
	assert.Nil(t, op)

	// check for duplicates in sec. requirements for operation
	pi.Get.Security = []map[string][]string{
		{"oauth2": {}},
		{"basic": nil},
		{"basic": nil},
	}
	spec = makeFixturepec(pi, pi2, formatParam)
	analyzer = New(spec)
	securityDefinitions = analyzer.SecurityDefinitionsFor(spec.Paths.Paths["/"].Get)
	assert.Len(t, securityDefinitions, 2)
	assert.Equal(t, *spec.SecurityDefinitions["basic"], securityDefinitions["basic"])
	assert.Equal(t, *spec.SecurityDefinitions["oauth2"], securityDefinitions["oauth2"])

	// check for empty (optional) in sec. requirements for operation
	pi.Get.Security = []map[string][]string{
		{"oauth2": {}},
		{"": nil},
		{"basic": nil},
	}
	spec = makeFixturepec(pi, pi2, formatParam)
	analyzer = New(spec)
	securityDefinitions = analyzer.SecurityDefinitionsFor(spec.Paths.Paths["/"].Get)
	assert.Len(t, securityDefinitions, 2)
	assert.Equal(t, *spec.SecurityDefinitions["basic"], securityDefinitions["basic"])
	assert.Equal(t, *spec.SecurityDefinitions["oauth2"], securityDefinitions["oauth2"])
}

func TestDefinitionAnalysis(t *testing.T) {
	doc, err := loadSpec(filepath.Join("fixtures", "definitions.yml"))
	if assert.NoError(t, err) {
		analyzer := New(doc)
		definitions := analyzer.allSchemas
		// parameters
		assertSchemaRefExists(t, definitions, "#/parameters/someParam/schema")
		assertSchemaRefExists(t, definitions, "#/paths/~1some~1where~1{id}/parameters/1/schema")
		assertSchemaRefExists(t, definitions, "#/paths/~1some~1where~1{id}/get/parameters/1/schema")
		// responses
		assertSchemaRefExists(t, definitions, "#/responses/someResponse/schema")
		assertSchemaRefExists(t, definitions, "#/paths/~1some~1where~1{id}/get/responses/default/schema")
		assertSchemaRefExists(t, definitions, "#/paths/~1some~1where~1{id}/get/responses/200/schema")
		// definitions
		assertSchemaRefExists(t, definitions, "#/definitions/tag")
		assertSchemaRefExists(t, definitions, "#/definitions/tag/properties/id")
		assertSchemaRefExists(t, definitions, "#/definitions/tag/properties/value")
		assertSchemaRefExists(t, definitions, "#/definitions/tag/definitions/category")
		assertSchemaRefExists(t, definitions, "#/definitions/tag/definitions/category/properties/id")
		assertSchemaRefExists(t, definitions, "#/definitions/tag/definitions/category/properties/value")
		assertSchemaRefExists(t, definitions, "#/definitions/withAdditionalProps")
		assertSchemaRefExists(t, definitions, "#/definitions/withAdditionalProps/additionalProperties")
		assertSchemaRefExists(t, definitions, "#/definitions/withAdditionalItems")
		assertSchemaRefExists(t, definitions, "#/definitions/withAdditionalItems/items/0")
		assertSchemaRefExists(t, definitions, "#/definitions/withAdditionalItems/items/1")
		assertSchemaRefExists(t, definitions, "#/definitions/withAdditionalItems/additionalItems")
		assertSchemaRefExists(t, definitions, "#/definitions/withNot")
		assertSchemaRefExists(t, definitions, "#/definitions/withNot/not")
		assertSchemaRefExists(t, definitions, "#/definitions/withAnyOf")
		assertSchemaRefExists(t, definitions, "#/definitions/withAnyOf/anyOf/0")
		assertSchemaRefExists(t, definitions, "#/definitions/withAnyOf/anyOf/1")
		assertSchemaRefExists(t, definitions, "#/definitions/withAllOf")
		assertSchemaRefExists(t, definitions, "#/definitions/withAllOf/allOf/0")
		assertSchemaRefExists(t, definitions, "#/definitions/withAllOf/allOf/1")
		assertSchemaRefExists(t, definitions, "#/definitions/withOneOf/oneOf/0")
		assertSchemaRefExists(t, definitions, "#/definitions/withOneOf/oneOf/1")
		allOfs := analyzer.allOfs
		assert.Len(t, allOfs, 1)
		assert.Contains(t, allOfs, "#/definitions/withAllOf")
	}
}

func loadSpec(path string) (*spec.Swagger, error) {
	spec.PathLoader = func(path string) (json.RawMessage, error) {
		ext := filepath.Ext(path)
		if ext == ".yml" || ext == ".yaml" {
			return fmts.YAMLDoc(path)
		}
		data, err := swag.LoadFromFileOrHTTP(path)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(data), nil
	}
	data, err := fmts.YAMLDoc(path)
	if err != nil {
		return nil, err
	}

	var sw spec.Swagger
	if err := json.Unmarshal(data, &sw); err != nil {
		return nil, err
	}
	return &sw, nil
}

func TestReferenceAnalysis(t *testing.T) {
	doc, err := loadSpec(filepath.Join("fixtures", "references.yml"))
	if assert.NoError(t, err) {
		an := New(doc)
		definitions := an.references

		// parameters
		assertRefExists(t, definitions.parameters, "#/paths/~1some~1where~1{id}/parameters/0")
		assertRefExists(t, definitions.parameters, "#/paths/~1some~1where~1{id}/get/parameters/0")

		// path items
		assertRefExists(t, definitions.pathItems, "#/paths/~1other~1place")

		// responses
		assertRefExists(t, definitions.responses, "#/paths/~1some~1where~1{id}/get/responses/404")

		// definitions
		assertRefExists(t, definitions.schemas, "#/responses/notFound/schema")
		assertRefExists(t, definitions.schemas, "#/paths/~1some~1where~1{id}/get/responses/200/schema")
		assertRefExists(t, definitions.schemas, "#/definitions/tag/properties/audit")

		// items
		// Supported non-swagger 2.0 constructs ($ref in simple schema items)
		assertRefExists(t, definitions.allRefs, "#/paths/~1some~1where~1{id}/get/parameters/1/items")
		assertRefExists(t, definitions.allRefs, "#/paths/~1some~1where~1{id}/get/parameters/2/items")
		assertRefExists(t, definitions.allRefs,
			"#/paths/~1some~1where~1{id}/get/responses/default/headers/x-array-header/items")

		assert.Lenf(t, an.AllItemsReferences(), 3, "Expected 3 items references in this spec")

		assertRefExists(t, definitions.parameterItems, "#/paths/~1some~1where~1{id}/get/parameters/1/items")
		assertRefExists(t, definitions.parameterItems, "#/paths/~1some~1where~1{id}/get/parameters/2/items")
		assertRefExists(t, definitions.headerItems,
			"#/paths/~1some~1where~1{id}/get/responses/default/headers/x-array-header/items")
	}
}

func assertRefExists(t testing.TB, data map[string]spec.Ref, key string) bool {
	if _, ok := data[key]; !ok {
		return assert.Fail(t, fmt.Sprintf("expected %q to exist in the ref bag", key))
	}
	return true
}

func assertSchemaRefExists(t testing.TB, data map[string]SchemaRef, key string) bool {
	if _, ok := data[key]; !ok {
		return assert.Fail(t, fmt.Sprintf("expected %q to exist in schema ref bag", key))
	}
	return true
}

func TestPatternAnalysis(t *testing.T) {
	doc, err := loadSpec(filepath.Join("fixtures", "patterns.yml"))
	if assert.NoError(t, err) {
		an := New(doc)
		pt := an.patterns

		// parameters
		assertPattern(t, pt.parameters, "#/parameters/idParam", "a[A-Za-Z0-9]+")
		assertPattern(t, pt.parameters, "#/paths/~1some~1where~1{id}/parameters/1", "b[A-Za-z0-9]+")
		assertPattern(t, pt.parameters, "#/paths/~1some~1where~1{id}/get/parameters/0", "[abc][0-9]+")

		// responses
		assertPattern(t, pt.headers, "#/responses/notFound/headers/ContentLength", "[0-9]+")
		assertPattern(t, pt.headers,
			"#/paths/~1some~1where~1{id}/get/responses/200/headers/X-Request-Id", "d[A-Za-z0-9]+")

		// definitions
		assertPattern(t, pt.schemas,
			"#/paths/~1other~1place/post/parameters/0/schema/properties/value", "e[A-Za-z0-9]+")
		assertPattern(t, pt.schemas, "#/paths/~1other~1place/post/responses/200/schema/properties/data", "[0-9]+[abd]")
		assertPattern(t, pt.schemas, "#/definitions/named", "f[A-Za-z0-9]+")
		assertPattern(t, pt.schemas, "#/definitions/tag/properties/value", "g[A-Za-z0-9]+")

		// items
		assertPattern(t, pt.items, "#/paths/~1some~1where~1{id}/get/parameters/1/items", "c[A-Za-z0-9]+")
		assertPattern(t, pt.items, "#/paths/~1other~1place/post/responses/default/headers/Via/items", "[A-Za-z]+")

		// patternProperties (beyond Swagger 2.0)
		_, ok := an.spec.Definitions["withPatternProperties"]
		assert.True(t, ok)
		_, ok = an.allSchemas["#/definitions/withPatternProperties/patternProperties/^prop[0-9]+$"]
		assert.True(t, ok)
	}
}

func assertPattern(t testing.TB, data map[string]string, key, pattern string) bool {
	if assert.Contains(t, data, key) {
		return assert.Equal(t, pattern, data[key])
	}
	return false
}

func panickerParamsAsMap() {
	s := prepareTestParamsInvalid("fixture-342.yaml")
	if s == nil {
		return
	}
	m := make(map[string]spec.Parameter)
	if pi, ok := s.spec.Paths.Paths["/fixture"]; ok {
		pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
		s.paramsAsMap(pi.Parameters, m, nil)
	}
}

func panickerParamsAsMap2() {
	s := prepareTestParamsInvalid("fixture-342-2.yaml")
	if s == nil {
		return
	}
	m := make(map[string]spec.Parameter)
	if pi, ok := s.spec.Paths.Paths["/fixture"]; ok {
		pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
		s.paramsAsMap(pi.Parameters, m, nil)
	}
}

func panickerParamsAsMap3() {
	s := prepareTestParamsInvalid("fixture-342-3.yaml")
	if s == nil {
		return
	}
	m := make(map[string]spec.Parameter)
	if pi, ok := s.spec.Paths.Paths["/fixture"]; ok {
		pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
		s.paramsAsMap(pi.Parameters, m, nil)
	}
}

func TestAnalyzer_paramsAsMap(Pt *testing.T) {
	s := prepareTestParamsValid()
	if assert.NotNil(Pt, s) {
		m := make(map[string]spec.Parameter)
		pi, ok := s.spec.Paths.Paths["/items"]
		if assert.True(Pt, ok) {
			s.paramsAsMap(pi.Parameters, m, nil)
			assert.Len(Pt, m, 1)
			p, ok := m["query#Limit"]
			assert.True(Pt, ok)
			assert.Equal(Pt, p.Name, "limit")
		}
	}

	// An invalid spec, but passes this step (errors are figured out at a higher level)
	s = prepareTestParamsInvalid("fixture-1289-param.yaml")
	if assert.NotNil(Pt, s) {
		m := make(map[string]spec.Parameter)
		pi, ok := s.spec.Paths.Paths["/fixture"]
		if assert.True(Pt, ok) {
			pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
			s.paramsAsMap(pi.Parameters, m, nil)
			assert.Len(Pt, m, 1)
			p, ok := m["body#DespicableMe"]
			assert.True(Pt, ok)
			assert.Equal(Pt, p.Name, "despicableMe")
		}
	}
}

func TestAnalyzer_paramsAsMapWithCallback(Pt *testing.T) {
	s := prepareTestParamsInvalid("fixture-342.yaml")
	if assert.NotNil(Pt, s) {
		// No bail out callback
		m := make(map[string]spec.Parameter)
		e := []string{}
		pi, ok := s.spec.Paths.Paths["/fixture"]
		if assert.True(Pt, ok) {
			pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
			s.paramsAsMap(pi.Parameters, m, func(param spec.Parameter, err error) bool {
				//Pt.Logf("ERROR on %+v : %v", param, err)
				e = append(e, err.Error())
				return true // Continue
			})
		}
		assert.Contains(Pt, e, `resolved reference is not a parameter: "#/definitions/sample_info/properties/sid"`)
		assert.Contains(Pt, e, `invalid reference: "#/definitions/sample_info/properties/sids"`)

		// bail out callback
		m = make(map[string]spec.Parameter)
		e = []string{}
		pi, ok = s.spec.Paths.Paths["/fixture"]
		if assert.True(Pt, ok) {
			pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
			s.paramsAsMap(pi.Parameters, m, func(param spec.Parameter, err error) bool {
				//Pt.Logf("ERROR on %+v : %v", param, err)
				e = append(e, err.Error())
				return false // Bail out
			})
		}
		// We got one then bail out
		assert.Len(Pt, e, 1)
	}

	// Bail out after ref failure: exercising another path
	s = prepareTestParamsInvalid("fixture-342-2.yaml")
	if assert.NotNil(Pt, s) {
		// bail out callback
		m := make(map[string]spec.Parameter)
		e := []string{}
		pi, ok := s.spec.Paths.Paths["/fixture"]
		if assert.True(Pt, ok) {
			pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
			s.paramsAsMap(pi.Parameters, m, func(param spec.Parameter, err error) bool {
				//Pt.Logf("ERROR on %+v : %v", param, err)
				e = append(e, err.Error())
				return false // Bail out
			})
		}
		// We got one then bail out
		assert.Len(Pt, e, 1)
	}

	// Bail out after ref failure: exercising another path
	s = prepareTestParamsInvalid("fixture-342-3.yaml")
	if assert.NotNil(Pt, s) {
		// bail out callback
		m := make(map[string]spec.Parameter)
		e := []string{}
		pi, ok := s.spec.Paths.Paths["/fixture"]
		if assert.True(Pt, ok) {
			pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
			s.paramsAsMap(pi.Parameters, m, func(param spec.Parameter, err error) bool {
				//Pt.Logf("ERROR on %+v : %v", param, err)
				e = append(e, err.Error())
				return false // Bail out
			})
		}
		// We got one then bail out
		assert.Len(Pt, e, 1)
	}
}

func TestAnalyzer_paramsAsMap_Panic(Pt *testing.T) {
	assert.Panics(Pt, panickerParamsAsMap)

	// Specifically on invalid resolved type
	assert.Panics(Pt, panickerParamsAsMap2)

	// Specifically on invalid ref
	assert.Panics(Pt, panickerParamsAsMap3)
}

func TestAnalyzer_SafeParamsFor(Pt *testing.T) {
	s := prepareTestParamsInvalid("fixture-342.yaml")
	if assert.NotNil(Pt, s) {
		e := []string{}
		pi, ok := s.spec.Paths.Paths["/fixture"]
		if assert.True(Pt, ok) {
			pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
			for range s.SafeParamsFor("Get", "/fixture", func(param spec.Parameter, err error) bool {
				e = append(e, err.Error())
				return true // Continue
			}) {
				assert.Fail(Pt, "There should be no safe parameter in this testcase")
			}
		}
		assert.Contains(Pt, e, `resolved reference is not a parameter: "#/definitions/sample_info/properties/sid"`)
		assert.Contains(Pt, e, `invalid reference: "#/definitions/sample_info/properties/sids"`)

	}
}

func panickerParamsFor() {
	s := prepareTestParamsInvalid("fixture-342.yaml")
	pi, ok := s.spec.Paths.Paths["/fixture"]
	if ok {
		pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
		s.ParamsFor("Get", "/fixture")
	}
}

func TestAnalyzer_ParamsFor(Pt *testing.T) {
	// Valid example
	s := prepareTestParamsValid()
	if assert.NotNil(Pt, s) {

		params := s.ParamsFor("Get", "/items")
		assert.True(Pt, len(params) > 0)
	}

	// Invalid example
	assert.Panics(Pt, panickerParamsFor)
}

func TestAnalyzer_SafeParametersFor(Pt *testing.T) {
	s := prepareTestParamsInvalid("fixture-342.yaml")
	if assert.NotNil(Pt, s) {
		e := []string{}
		pi, ok := s.spec.Paths.Paths["/fixture"]
		if assert.True(Pt, ok) {
			pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
			for range s.SafeParametersFor("fixtureOp", func(param spec.Parameter, err error) bool {
				e = append(e, err.Error())
				return true // Continue
			}) {
				assert.Fail(Pt, "There should be no safe parameter in this testcase")
			}
		}
		assert.Contains(Pt, e, `resolved reference is not a parameter: "#/definitions/sample_info/properties/sid"`)
		assert.Contains(Pt, e, `invalid reference: "#/definitions/sample_info/properties/sids"`)
	}
}

func panickerParametersFor() {
	s := prepareTestParamsInvalid("fixture-342.yaml")
	if s == nil {
		return
	}
	pi, ok := s.spec.Paths.Paths["/fixture"]
	if ok {
		pi.Parameters = pi.PathItemProps.Get.OperationProps.Parameters
		//func (s *Spec) ParametersFor(operationID string) []spec.Parameter {
		s.ParametersFor("fixtureOp")
	}
}

func TestAnalyzer_ParametersFor(Pt *testing.T) {
	// Valid example
	s := prepareTestParamsValid()
	params := s.ParamsFor("Get", "/items")
	assert.True(Pt, len(params) > 0)

	// Invalid example
	assert.Panics(Pt, panickerParametersFor)
}

func prepareTestParamsValid() *Spec {
	formatParam := spec.QueryParam("format").Typed("string", "")

	limitParam := spec.QueryParam("limit").Typed("integer", "int32")
	limitParam.Extensions = spec.Extensions(map[string]interface{}{})
	limitParam.Extensions.Add("go-name", "Limit")

	skipParam := spec.QueryParam("skip").Typed("integer", "int32")
	pi := spec.PathItem{}
	pi.Parameters = []spec.Parameter{*limitParam}

	op := &spec.Operation{}
	op.Consumes = []string{"application/x-yaml"}
	op.Produces = []string{"application/x-yaml"}
	op.Security = []map[string][]string{
		{"oauth2": {}},
		{"basic": nil},
	}
	op.ID = "someOperation"
	op.Parameters = []spec.Parameter{*skipParam}
	pi.Get = op

	pi2 := spec.PathItem{}
	pi2.Parameters = []spec.Parameter{*limitParam}
	op2 := &spec.Operation{}
	op2.ID = "anotherOperation"
	op2.Parameters = []spec.Parameter{*skipParam}
	pi2.Get = op2

	spec := makeFixturepec(pi, pi2, formatParam)
	analyzer := New(spec)
	return analyzer
}

func prepareTestParamsInvalid(fixture string) *Spec {
	cwd, _ := os.Getwd()
	bp := filepath.Join(cwd, "fixtures", fixture)
	spec, err := loadSpec(bp)
	if err != nil {
		log.Printf("Warning: fixture %s could not be loaded: %v", fixture, err)
		return nil
	}
	analyzer := New(spec)
	return analyzer
}

func TestSecurityDefinitionsFor(t *testing.T) {
	spec := prepareTestParamsAuth()
	pi1 := spec.spec.Paths.Paths["/"].Get
	pi2 := spec.spec.Paths.Paths["/items"].Get

	defs1 := spec.SecurityDefinitionsFor(pi1)
	require.Contains(t, defs1, "oauth2")
	require.Contains(t, defs1, "basic")
	require.NotContains(t, defs1, "apiKey")

	defs2 := spec.SecurityDefinitionsFor(pi2)
	require.Contains(t, defs2, "oauth2")
	require.Contains(t, defs2, "basic")
	require.Contains(t, defs2, "apiKey")
}

func TestSecurityRequirements(t *testing.T) {
	spec := prepareTestParamsAuth()
	pi1 := spec.spec.Paths.Paths["/"].Get
	pi2 := spec.spec.Paths.Paths["/items"].Get
	scopes := []string{"the-scope"}

	reqs1 := spec.SecurityRequirementsFor(pi1)
	require.Len(t, reqs1, 2)
	require.Len(t, reqs1[0], 1)
	require.Equal(t, reqs1[0][0].Name, "oauth2")
	require.Equal(t, reqs1[0][0].Scopes, scopes)
	require.Len(t, reqs1[1], 1)
	require.Equal(t, reqs1[1][0].Name, "basic")
	require.Empty(t, reqs1[1][0].Scopes)

	reqs2 := spec.SecurityRequirementsFor(pi2)
	require.Len(t, reqs2, 3)
	require.Len(t, reqs2[0], 1)
	require.Equal(t, reqs2[0][0].Name, "oauth2")
	require.Equal(t, reqs2[0][0].Scopes, scopes)
	require.Len(t, reqs2[1], 1)
	require.Empty(t, reqs2[1][0].Name)
	require.Empty(t, reqs2[1][0].Scopes)
	require.Len(t, reqs2[2], 2)
	//
	//require.Equal(t, reqs2[2][0].Name, "basic")
	require.Contains(t, reqs2[2], SecurityRequirement{Name: "basic", Scopes: []string{}})
	require.Empty(t, reqs2[2][0].Scopes)
	//require.Equal(t, reqs2[2][1].Name, "apiKey")
	require.Contains(t, reqs2[2], SecurityRequirement{Name: "apiKey", Scopes: []string{}})
	require.Empty(t, reqs2[2][1].Scopes)
}

func TestSecurityRequirementsDefinitions(t *testing.T) {
	spec := prepareTestParamsAuth()
	pi1 := spec.spec.Paths.Paths["/"].Get
	pi2 := spec.spec.Paths.Paths["/items"].Get

	reqs1 := spec.SecurityRequirementsFor(pi1)
	defs11 := spec.SecurityDefinitionsForRequirements(reqs1[0])
	require.Contains(t, defs11, "oauth2")
	defs12 := spec.SecurityDefinitionsForRequirements(reqs1[1])
	require.Contains(t, defs12, "basic")
	require.NotContains(t, defs12, "apiKey")

	reqs2 := spec.SecurityRequirementsFor(pi2)
	defs21 := spec.SecurityDefinitionsForRequirements(reqs2[0])
	require.Len(t, defs21, 1)
	require.Contains(t, defs21, "oauth2")
	require.NotContains(t, defs21, "basic")
	require.NotContains(t, defs21, "apiKey")
	defs22 := spec.SecurityDefinitionsForRequirements(reqs2[1])
	require.NotNil(t, defs22)
	require.Empty(t, defs22)
	defs23 := spec.SecurityDefinitionsForRequirements(reqs2[2])
	require.Len(t, defs23, 2)
	require.NotContains(t, defs23, "oauth2")
	require.Contains(t, defs23, "basic")
	require.Contains(t, defs23, "apiKey")

}

func prepareTestParamsAuth() *Spec {
	formatParam := spec.QueryParam("format").Typed("string", "")

	limitParam := spec.QueryParam("limit").Typed("integer", "int32")
	limitParam.Extensions = spec.Extensions(map[string]interface{}{})
	limitParam.Extensions.Add("go-name", "Limit")

	skipParam := spec.QueryParam("skip").Typed("integer", "int32")
	pi := spec.PathItem{}
	pi.Parameters = []spec.Parameter{*limitParam}

	op := &spec.Operation{}
	op.Consumes = []string{"application/x-yaml"}
	op.Produces = []string{"application/x-yaml"}
	op.Security = []map[string][]string{
		{"oauth2": {"the-scope"}},
		{"basic": nil},
	}
	op.ID = "someOperation"
	op.Parameters = []spec.Parameter{*skipParam}
	pi.Get = op

	pi2 := spec.PathItem{}
	pi2.Parameters = []spec.Parameter{*limitParam}
	op2 := &spec.Operation{}
	op2.ID = "anotherOperation"
	op2.Security = []map[string][]string{
		{"oauth2": {"the-scope"}},
		{},
		{
			"basic":  {},
			"apiKey": {},
		},
	}
	op2.Parameters = []spec.Parameter{*skipParam}
	pi2.Get = op2

	oauth := spec.OAuth2AccessToken("http://authorize.com", "http://token.com")
	oauth.AddScope("the-scope", "the scope gives access to ...")
	spec := &spec.Swagger{
		SwaggerProps: spec.SwaggerProps{
			Consumes: []string{"application/json"},
			Produces: []string{"application/json"},
			Security: []map[string][]string{
				{"apikey": nil},
			},
			SecurityDefinitions: map[string]*spec.SecurityScheme{
				"basic":  spec.BasicAuth(),
				"apiKey": spec.APIKeyAuth("api_key", "query"),
				"oauth2": oauth,
			},
			Parameters: map[string]spec.Parameter{"format": *formatParam},
			Paths: &spec.Paths{
				Paths: map[string]spec.PathItem{
					"/":      pi,
					"/items": pi2,
				},
			},
		},
	}
	analyzer := New(spec)
	return analyzer
}

func TestMoreParamAnalysis(t *testing.T) {
	cwd, _ := os.Getwd()
	bp := filepath.Join(cwd, "fixtures", "parameters", "fixture-parameters.yaml")
	sp, err := loadSpec(bp)
	if !assert.NoError(t, err) {
		t.FailNow()
		return
	}

	an := New(sp)

	res := an.AllPatterns()
	assert.Lenf(t, res, 6, "Expected 6 patterns in this spec")

	res = an.SchemaPatterns()
	assert.Lenf(t, res, 1, "Expected 1 schema pattern in this spec")

	res = an.HeaderPatterns()
	assert.Lenf(t, res, 2, "Expected 2 header pattern in this spec")

	res = an.ItemsPatterns()
	assert.Lenf(t, res, 2, "Expected 2 items pattern in this spec")

	res = an.ParameterPatterns()
	assert.Lenf(t, res, 1, "Expected 1 simple param pattern in this spec")

	refs := an.AllRefs()
	assert.Lenf(t, refs, 10, "Expected 10 reference usage in this spec")

	references := an.AllReferences()
	assert.Lenf(t, references, 14, "Expected 14 reference usage in this spec")

	references = an.AllItemsReferences()
	assert.Lenf(t, references, 0, "Expected 0 items reference in this spec")

	references = an.AllPathItemReferences()
	assert.Lenf(t, references, 1, "Expected 1 pathItem reference in this spec")

	references = an.AllResponseReferences()
	assert.Lenf(t, references, 3, "Expected 3 response references in this spec")

	references = an.AllParameterReferences()
	assert.Lenf(t, references, 6, "Expected 6 parameter references in this spec")

	schemaRefs := an.AllDefinitions()
	assert.Lenf(t, schemaRefs, 14, "Expected 14 schema definitions in this spec")
	//for _, refs := range schemaRefs {
	//	t.Logf("Schema Ref: %s (%s)", refs.Name, refs.Ref.String())
	//}
	schemaRefs = an.SchemasWithAllOf()
	assert.Lenf(t, schemaRefs, 1, "Expected 1 schema with AllOf definition in this spec")

	method, path, op, found := an.OperationForName("postSomeWhere")
	assert.Equal(t, "POST", method)
	assert.Equal(t, "/some/where", path)
	if assert.NotNil(t, op) && assert.True(t, found) {
		sec := an.SecurityRequirementsFor(op)
		assert.Nil(t, sec)
		secScheme := an.SecurityDefinitionsFor(op)
		assert.Nil(t, secScheme)

		bag := an.ParametersFor("postSomeWhere")
		assert.Lenf(t, bag, 6, "Expected 6 parameters for this operation")
	}

	method, path, op, found = an.OperationForName("notFound")
	assert.Equal(t, "", method)
	assert.Equal(t, "", path)
	assert.Nil(t, op)
	assert.False(t, found)

	// does not take ops under pathItem $ref
	ops := an.OperationMethodPaths()
	assert.Lenf(t, ops, 3, "Expected 3 ops")
	ops = an.OperationIDs()
	assert.Lenf(t, ops, 3, "Expected 3 ops")
	assert.Contains(t, ops, "postSomeWhere")
	assert.Contains(t, ops, "GET /some/where/else")
	assert.Contains(t, ops, "GET /some/where")
}

func Test_EdgeCases(t *testing.T) {
	// check return values are consistent in some nil/empty edge cases
	sp := Spec{}
	res1 := sp.AllPaths()
	assert.Nil(t, res1)

	res2 := sp.OperationIDs()
	assert.Nil(t, res2)

	res3 := sp.OperationMethodPaths()
	assert.Nil(t, res3)

	res4 := sp.structMapKeys(nil)
	assert.Nil(t, res4)

	res5 := sp.structMapKeys(make(map[string]struct{}, 10))
	assert.Nil(t, res5)

	// check AllRefs() skips empty $refs
	sp.references.allRefs = make(map[string]spec.Ref, 3)
	for i := 0; i < 3; i++ {
		sp.references.allRefs["ref"+strconv.Itoa(i)] = spec.Ref{}
	}
	assert.Len(t, sp.references.allRefs, 3)
	res6 := sp.AllRefs()
	assert.Len(t, res6, 0)

	// check AllRefs() skips duplicate $refs
	sp.references.allRefs["refToOne"] = spec.MustCreateRef("#/ref1")
	sp.references.allRefs["refToOneAgain"] = spec.MustCreateRef("#/ref1")
	res7 := sp.AllRefs()
	assert.NotNil(t, res7)
	assert.Len(t, res7, 1)
}
