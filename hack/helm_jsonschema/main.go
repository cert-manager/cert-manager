//go:build exclude

/*
Copyright 2022 The Kubernetes Authors.
Started from https://github.com/kubernetes/kubernetes/blob/f5956716e3a92fba30c81635c68187653f7567c2/pkg/generated/openapi/cmd/models-schema/main.go
*/

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/hack/helm_jsonschema/openapi"
	"k8s.io/kube-openapi/pkg/common"
	"k8s.io/kube-openapi/pkg/validation/spec"
)

// Outputs openAPI schema JSON containing the schema definitions in zz_generated.openapi.go.
func main() {
	err := output()
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("Failed: %v", err))
		os.Exit(1)
	}
}

func pruneDefinitions(name string, from, to map[string]common.OpenAPIDefinition) {
	if _, ok := to[name]; ok {
		return
	}

	for _, dep := range from[name].Dependencies {
		pruneDefinitions(dep, from, to)
	}

	to[name] = from[name]
}

type JsonSchema struct {
	Schema string           `json:"$schema,omitempty"`
	Ref    string           `json:"$ref,omitempty"`
	Defs   spec.Definitions `json:"$defs,omitempty"`
}

func output() error {
	refFunc := func(name string) spec.Ref {
		return spec.MustCreateRef(fmt.Sprintf("#/$defs/%s", friendlyName(name)))
	}
	fromDefs := openapi.GetOpenAPIDefinitions(refFunc)

	defs := map[string]common.OpenAPIDefinition{}
	start := "github.com/cert-manager/cert-manager/deploy/charts/cert-manager/values.HelmValues"
	pruneDefinitions(start, fromDefs, defs)

	schemaDefs := make(map[string]spec.Schema, len(defs))
	for k, v := range defs {
		// Replace top-level schema with v2 if a v2 schema is embedded
		// so that the output of this program is always in OpenAPI v2.
		// This is done by looking up an extension that marks the embedded v2
		// schema, and, if the v2 schema is found, make it the resulting schema for
		// the type.
		if schema, ok := v.Schema.Extensions[common.ExtensionV2Schema]; ok {
			if v2Schema, isOpenAPISchema := schema.(spec.Schema); isOpenAPISchema {
				schemaDefs[friendlyName(k)] = v2Schema
				continue
			}
		}

		if v.Schema.AdditionalProperties == nil {
			// default to false
			v.Schema.AdditionalProperties = &spec.SchemaOrBool{Allows: false}
		}

		schemaDefs[friendlyName(k)] = v.Schema
	}

	data, err := json.Marshal(JsonSchema{
		Schema: "http://json-schema.org/draft-07/schema#",
		Defs:   schemaDefs,
		Ref:    "#/$defs/" + friendlyName(start),
	})
	if err != nil {
		return fmt.Errorf("error serializing api definitions: %w", err)
	}
	os.Stdout.Write(data)
	return nil
}

// From vendor/k8s.io/apiserver/pkg/endpoints/openapi/openapi.go
func friendlyName(name string) string {
	nameParts := strings.Split(name, "/")
	// Reverse first part. e.g., io.k8s... instead of k8s.io...
	if len(nameParts) > 0 && strings.Contains(nameParts[0], ".") {
		parts := strings.Split(nameParts[0], ".")
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		nameParts[0] = strings.Join(parts, ".")
	}
	return strings.Join(nameParts, ".")
}
