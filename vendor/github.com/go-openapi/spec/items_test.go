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

var items = Items{
	Refable: Refable{Ref: MustCreateRef("Dog")},
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
	SimpleSchema: SimpleSchema{
		Type:   "string",
		Format: "date",
		Items: &Items{
			Refable: Refable{Ref: MustCreateRef("Cat")},
		},
		CollectionFormat: "csv",
		Default:          "8",
	},
}

var itemsJSON = `{
	"items": {
		"$ref": "Cat"
	},
  "$ref": "Dog",
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
	"collectionFormat": "csv",
	"default": "8"
}`

func TestIntegrationItems(t *testing.T) {
	var actual Items
	if assert.NoError(t, json.Unmarshal([]byte(itemsJSON), &actual)) {
		assert.EqualValues(t, actual, items)
	}

	assertParsesJSON(t, itemsJSON, items)
}

func TestTypeNameItems(t *testing.T) {
	var nilItems Items
	assert.Equal(t, "", nilItems.TypeName())

	assert.Equal(t, "date", items.TypeName())
	assert.Equal(t, "", items.ItemsTypeName())

	nested := Items{
		SimpleSchema: SimpleSchema{
			Type: "array",
			Items: &Items{
				SimpleSchema: SimpleSchema{
					Type:   "integer",
					Format: "int32",
				},
			},
			CollectionFormat: "csv",
		},
	}

	assert.Equal(t, "array", nested.TypeName())
	assert.Equal(t, "int32", nested.ItemsTypeName())
}

func TestJSONLookupItems(t *testing.T) {
	res, err := items.JSONLookup("$ref")
	if !assert.NoError(t, err) {
		t.FailNow()
		return
	}
	if assert.IsType(t, &Ref{}, res) {
		ref := res.(*Ref)
		assert.EqualValues(t, MustCreateRef("Dog"), *ref)
	}

	var max *float64
	res, err = items.JSONLookup("maximum")
	if !assert.NoError(t, err) || !assert.NotNil(t, res) || !assert.IsType(t, max, res) {
		t.FailNow()
		return
	}
	max = res.(*float64)
	assert.Equal(t, float64(100), *max)

	var f string
	res, err = items.JSONLookup("collectionFormat")
	if !assert.NoError(t, err) || !assert.NotNil(t, res) || !assert.IsType(t, f, res) {
		t.FailNow()
		return
	}
	f = res.(string)
	assert.Equal(t, "csv", f)

	res, err = items.JSONLookup("unknown")
	if !assert.Error(t, err) || !assert.Nil(t, res) {
		t.FailNow()
		return
	}
}
