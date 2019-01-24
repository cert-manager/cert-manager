/*
Copyright 2018 The Kubernetes Authors.

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

package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"github.com/emicklei/go-restful"
	"github.com/go-openapi/spec"
	"k8s.io/kube-openapi/pkg/builder"
	"k8s.io/kube-openapi/pkg/common"
	"k8s.io/kube-openapi/test/integration/pkg/generated"
)

// TODO: Change this to output the generated swagger to stdout.
const defaultSwaggerFile = "generated.json"

func main() {
	// Get the name of the generated swagger file from the args
	// if it exists; otherwise use the default file name.
	swaggerFilename := defaultSwaggerFile
	if len(os.Args) > 1 {
		swaggerFilename = os.Args[1]
	}

	// Generate the definition names from the map keys returned
	// from GetOpenAPIDefinitions. Anonymous function returning empty
	// Ref is not used.
	var defNames []string
	for name, _ := range generated.GetOpenAPIDefinitions(func(name string) spec.Ref {
		return spec.Ref{}
	}) {
		defNames = append(defNames, name)
	}

	// Create a minimal builder config, then call the builder with the definition names.
	config := createOpenAPIBuilderConfig()
	config.GetDefinitions = generated.GetOpenAPIDefinitions
	// Build the Paths using a simple WebService for the final spec
	swagger, serr := builder.BuildOpenAPISpec(createWebServices(), config)
	if serr != nil {
		log.Fatalf("ERROR: %s", serr.Error())
	}
	// Generate the definitions for the passed type names to put in the final spec.
	// Note that in reality one should run BuildOpenAPISpec to build the entire spec. We
	// separate the steps of building Paths and building Definitions here, because we
	// only have a simple WebService which doesn't wire the definitions up.
	definitionSwagger, err := builder.BuildOpenAPIDefinitionsForResources(config, defNames...)
	if err != nil {
		log.Fatalf("ERROR: %s", err.Error())
	}
	// Copy the generated definitions into the final swagger.
	swagger.Definitions = definitionSwagger.Definitions

	// Marshal the swagger spec into JSON, then write it out.
	specBytes, err := json.MarshalIndent(swagger, " ", " ")
	if err != nil {
		log.Fatalf("json marshal error: %s", err.Error())
	}
	err = ioutil.WriteFile(swaggerFilename, specBytes, 0644)
	if err != nil {
		log.Fatalf("stdout write error: %s", err.Error())
	}
}

// CreateOpenAPIBuilderConfig hard-codes some values in the API builder
// config for testing.
func createOpenAPIBuilderConfig() *common.Config {
	return &common.Config{
		ProtocolList:   []string{"https"},
		IgnorePrefixes: []string{"/swaggerapi"},
		Info: &spec.Info{
			InfoProps: spec.InfoProps{
				Title:   "Integration Test",
				Version: "1.0",
			},
		},
		ResponseDefinitions: map[string]spec.Response{
			"NotFound": spec.Response{
				ResponseProps: spec.ResponseProps{
					Description: "Entity not found.",
				},
			},
		},
		CommonResponses: map[int]spec.Response{
			404: *spec.ResponseRef("#/responses/NotFound"),
		},
	}
}

// createWebServices hard-codes a simple WebService which only defines a GET path
// for testing.
func createWebServices() []*restful.WebService {
	w := new(restful.WebService)
	// Define a dummy GET /test endpoint
	w = w.Route(w.GET("test").
		To(func(*restful.Request, *restful.Response) {}))
	return []*restful.WebService{w}
}
