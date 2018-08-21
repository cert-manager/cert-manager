/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"fmt"
	"github.com/go-openapi/spec"
	"strings"
)

var INLINE_DEFINITIONS = []InlineDefinition{
	{Name: "Spec", Match: "${resource}Spec"},
	{Name: "Status", Match: "${resource}Status"},
	{Name: "List", Match: "${resource}List"},
	{Name: "Strategy", Match: "${resource}Strategy"},
	{Name: "Rollback", Match: "${resource}Rollback"},
	{Name: "RollingUpdate", Match: "RollingUpdate${resource}"},
	{Name: "EventSource", Match: "${resource}EventSource"},
}

// Inline definitions for "Spec", "Status", "List", etc for definitions
func (definitions Definitions) InitInlinedDefinitions() Definitions {
	for _, d := range definitions.GetAllDefinitions() {
		for _, name := range definitions.GetInlinedDefinitionNames(d.Name) {
			if cr, found := definitions.GetByVersionKind(string(d.Group), string(d.Version), name); found {
				d.Inline = append(d.Inline, cr)
				cr.IsInlined = true
				cr.FoundInField = true
			}
		}
	}
	return definitions
}

// Build the "Appears In" index for definitions
func (definitions Definitions) InitAppearsIn() Definitions {
	for _, d := range definitions.GetAllDefinitions() {
		for _, child := range getDefinitionFieldDefinitions(d, definitions) {
			child.AppearsIn = append(child.AppearsIn, d)
			child.FoundInField = true
		}
	}
	return definitions
}

func getDefinitionFieldDefinitions(definition *Definition, definitions Definitions) []*Definition {
	children := []*Definition{}
	// Find all of the resources referenced by this definition
	for _, p := range definition.schema.Properties {
		if !definitions.IsComplex(p) {
			// Skip primitive types and collections of primitive types
			continue
		}
		// Look up the definition for the referenced resource
		if child, found := definitions.GetForSchema(p); found {
			children = append(children, child)
		} else {
			g, v, k := GetDefinitionVersionKind(p)
			fmt.Printf("Could not locate referenced property of %s: %s (%s/%s).\n", definition.Name, g, k, v)
		}
	}
	return children
}

func (c *Definitions) GetInlinedDefinitionNames(parent string) []string {
	names := []string{}
	for _, id := range INLINE_DEFINITIONS {
		name := strings.Replace(id.Match, "${resource}", parent, -1)
		names = append(names, name)
	}
	return names
}

func (definitions *Definitions) parameterToField(parameter spec.Parameter) *Field {
	field := &Field{
		Name:        parameter.Name,
		Description: strings.Replace(parameter.Description, "\n", " ", -1),
	}
	if parameter.Schema != nil {
		field.Type = GetTypeName(*parameter.Schema)
		if fieldType, f := definitions.GetForSchema(*parameter.Schema); f {
			field.Definition = fieldType
		}
	}
	return field
}
