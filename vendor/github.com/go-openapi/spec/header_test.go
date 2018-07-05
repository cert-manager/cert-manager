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

package spec

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func float64Ptr(f float64) *float64 {
	return &f
}
func int64Ptr(f int64) *int64 {
	return &f
}

var header = Header{
	VendorExtensible: VendorExtensible{Extensions: map[string]interface{}{
		"x-framework": "swagger-go",
	}},
	HeaderProps: HeaderProps{Description: "the description of this header"},
	SimpleSchema: SimpleSchema{
		Items: &Items{
			Refable: Refable{Ref: MustCreateRef("Cat")},
		},
		Type:    "string",
		Format:  "date",
		Default: "8",
	},
	CommonValidations: CommonValidations{
		Maximum:          float64Ptr(100),
		ExclusiveMaximum: true,
		ExclusiveMinimum: true,
		Minimum:          float64Ptr(5),
		MaxLength:        int64Ptr(100),
		MinLength:        int64Ptr(5),
		Pattern:          "\\w{1,5}\\w+",
		MaxItems:         int64Ptr(100),
		MinItems:         int64Ptr(5),
		UniqueItems:      true,
		MultipleOf:       float64Ptr(5),
		Enum:             []interface{}{"hello", "world"},
	},
}

var headerJSON = `{
  "items": {
    "$ref": "Cat"
  },
  "x-framework": "swagger-go",
  "description": "the description of this header",
  "maximum": 100,
  "minimum": 5,
  "exclusiveMaximum": true,
  "exclusiveMinimum": true,
  "maxLength": 100,
  "minLength": 5,
  "pattern": "\\w{1,5}\\w+",
  "maxItems": 100,
  "minItems": 5,
  "uniqueItems": true,
  "multipleOf": 5,
  "enum": ["hello", "world"],
  "type": "string",
  "format": "date",
  "default": "8"
}`

func TestIntegrationHeader(t *testing.T) {
	var actual Header
	if assert.NoError(t, json.Unmarshal([]byte(headerJSON), &actual)) {
		assert.EqualValues(t, actual, header)
	}

	assertParsesJSON(t, headerJSON, header)
}

func TestJSONLookupHeader(t *testing.T) {
	var def string
	res, err := header.JSONLookup("default")
	if !assert.NoError(t, err) || !assert.NotNil(t, res) || !assert.IsType(t, def, res) {
		t.FailNow()
		return
	}
	def = res.(string)
	assert.Equal(t, "8", def)

	var x *interface{}
	res, err = header.JSONLookup("x-framework")
	if !assert.NoError(t, err) || !assert.NotNil(t, res) || !assert.IsType(t, x, res) {
		t.FailNow()
		return
	}

	x = res.(*interface{})
	assert.EqualValues(t, "swagger-go", *x)

	res, err = header.JSONLookup("unknown")
	if !assert.Error(t, err) || !assert.Nil(t, res) {
		t.FailNow()
		return
	}

	var max *float64
	res, err = header.JSONLookup("maximum")
	if !assert.NoError(t, err) || !assert.NotNil(t, res) || !assert.IsType(t, max, res) {
		t.FailNow()
		return
	}
	max = res.(*float64)
	assert.Equal(t, float64(100), *max)
}
