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
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"html"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var AllowErrors = flag.Bool("allow-errors", false, "If true, don't fail on errors.")
var ConfigDir = flag.String("config-dir", "", "Directory contain api files.")

func NewConfig() *Config {
	config := loadYamlConfig()
	specs := LoadOpenApiSpec()
	//fmt.Printf("SPEC: %v\n\n", specs)

	// Initialize all of the operations
	config.Definitions = GetDefinitions(specs, config.VisitResourcesInToc)

	config.Definitions.InitAppearsIn()
	config.Definitions.InitInlinedDefinitions()

	// Initialization for ToC resources only
	vistToc := func(resource *Resource, definition *Definition) {
		definition.InToc = true // Mark as in Toc
		resource.Definition = definition
		config.initDefExample(definition) // Init the example yaml
	}
	config.VisitResourcesInToc(config.Definitions, vistToc)

	// In the descriptions, replace unicode escape sequences with HTML entities.
	config.createDescriptionsWithEntities()
	config.CleanUp()
	return config
}

func WalkFields(definition *Definition) {
	definition.IsReferenced = true
	for _, f := range definition.Fields {
		if f.Definition != nil {
			WalkFields(f.Definition)
		}
	}
	for _, d := range definition.OtherVersions {
		if !d.IsReferenced {
			WalkFields(d)
		}
	}
}

// CleanUp sorts and dedups fields
func (c *Config) CleanUp() {
	for _, d := range c.Definitions.GetAllDefinitions() {
		sort.Sort(d.AppearsIn)
		sort.Sort(d.Fields)
		dedup := SortDefinitionsByName{}
		var last *Definition
		for _, i := range d.AppearsIn {
			if last != nil &&
				i.Name == last.Name &&
				i.Group.String() == last.Group.String() &&
				i.Version.String() == last.Version.String() {
				continue
			}
			last = i
			dedup = append(dedup, i)
		}
		d.AppearsIn = dedup
	}
}

// loadYamlConfig reads the config yaml file into a struct
func loadYamlConfig() *Config {
	f := filepath.Join(*ConfigDir, "config.yaml")

	config := &Config{}
	contents, err := ioutil.ReadFile(f)
	if err != nil {
		fmt.Printf("Failed to read yaml file %s: %v", f, err)
		os.Exit(2)
	} else {
		err = yaml.Unmarshal(contents, config)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	return config
}

func (config *Config) GetDefExampleFile(d *Definition) string {
	return strings.Replace(strings.ToLower(filepath.Join(*ConfigDir, config.ExampleLocation, d.Name, d.Name+".yaml")), " ", "_", -1)
}

func (config *Config) initDefExample(d *Definition) {
	content, err := ioutil.ReadFile(config.GetDefExampleFile(d))
	if err != nil || len(content) <= 0 {
		//fmt.Printf("Missing example: %s %v\n", d.Name, err)
		return
	}
	err = yaml.Unmarshal(content, &d.Sample)
	if err != nil {
		panic(fmt.Sprintf("Could not Unmarshal SampleConfig yaml: %s\n", content))
	}
}

func (config *Config) createDescriptionsWithEntities() {

	// The OpenAPI spec has escape sequences like \u003c. When the spec is unmarshaled,
	// the escape sequences get converted to ordinary characters. For example,
	// \u003c gets converted to a regular < character. But we can't use  regular <
	// and > characters in our HTML document. This function replaces these regular
	// characters with HTML entities: <, >, &, ', and ".

	for _, definition := range config.Definitions.GetAllDefinitions() {
		d := definition.Description()
		d = html.EscapeString(d)
		definition.DescriptionWithEntities = d

		for _, field := range definition.Fields {
			d := field.Description
			d = html.EscapeString(d)
			field.DescriptionWithEntities = d
		}
	}

	for _, operation := range config.Operations {

		for _, field := range operation.BodyParams {
			d := field.Description
			d = html.EscapeString(d)
			field.DescriptionWithEntities = d
		}

		for _, field := range operation.QueryParams {
			d := field.Description
			d = html.EscapeString(d)
			field.DescriptionWithEntities = d
		}

		for _, field := range operation.PathParams {
			d := field.Description
			d = html.EscapeString(d)
			field.DescriptionWithEntities = d
		}

		for _, resp := range operation.HttpResponses {
			d := resp.Description
			d = html.EscapeString(d)
			resp.DescriptionWithEntities = d
		}
	}
}
