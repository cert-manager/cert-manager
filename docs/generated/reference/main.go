/*
Copyright YEAR Jetstack Ltd.

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
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"github.com/go-openapi/spec"
	"k8s.io/kube-openapi/pkg/common"

	"github.com/jetstack/cert-manager/docs/generated/reference/openapi"
)

func main() {
	WriteOpenAPI(openapi.GetOpenAPIDefinitions)
}

// WriteOpenAPI writes the openapi json to docs/reference/openapi-spec/swagger.json
func WriteOpenAPI(openapi func(ref common.ReferenceCallback) map[string]common.OpenAPIDefinition) {
	defs := openapi(func(name string) spec.Ref {
		parts := strings.Split(name, "/")
		return spec.MustCreateRef(fmt.Sprintf("#/definitions/%s.%s",
			common.EscapeJsonPointer(parts[len(parts)-2]),
			common.EscapeJsonPointer(parts[len(parts)-1])))
	})

	o, err := json.MarshalIndent(defs, "", "    ")
	if err != nil {
		log.Fatalf("Could not Marshal JSON %v\n%v", err, defs)
	}
	err = ioutil.WriteFile(filepath.Join("docs", "generated", "reference", "openapi-spec", "swagger.json"), o, 0700)
	if err != nil {
		log.Fatalf("%v", err)
	}
}
