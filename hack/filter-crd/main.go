/*
Copyright 2020 The cert-manager Authors.

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
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

var removeKeys = []string{}

func main() {
	loadVariant()

	if len(flag.Args()) < 1 {
		log.Fatal("Usage: filter-crd <CRD YAML file>")
	}

	f, err := os.Open(flag.Args()[0])
	if err != nil {
		log.Fatal("Error opening file: ", err)
	}

	decoder := yaml.NewDecoder(f)
	var d map[interface{}]interface{}
	output := []string{}

	for decoder.Decode(&d) == nil {

		if len(d) == 0 {
			continue
		}

		checkChain(d, []string{})

		fileOut, err := yaml.Marshal(d)
		if err != nil {
			log.Fatal("Error marshaling output: ", err)
		}

		output = append(output, string(fileOut))
		d = map[interface{}]interface{}{} // clean out the old, otherwise the decoder will merge keys
	}

	fmt.Println(strings.Join(output, "---\n"))
}

func checkChain(d map[interface{}]interface{}, chain []string) {
	for k, v := range d {
		if key, ok := k.(string); ok {
			chain = append(chain, key)

			// check if keys need to be removed
			for _, removeKey := range removeKeys {
				if strings.Join(chain, "/") == removeKey {
					delete(d, key)
				}
			}

			if value, ok := v.(map[interface{}]interface{}); ok {
				checkChain(value, chain)
			}
			if value, ok := v.([]interface{}); ok {
				d[k] = checkSliceChain(value, append(chain, "[]"))
			}
			chain = chain[:len(chain)-1] // we're done with this key, remove it from the chain
		}
	}
}

func checkSliceChain(s []interface{}, chain []string) []interface{} {
	for _, sliceVal := range s {
		if d, ok := sliceVal.(map[interface{}]interface{}); ok {
			for k, v := range d {
				if key, ok := k.(string); ok {
					chain = append(chain, key)

					// check if keys need to be removed
					for _, removeKey := range removeKeys {
						if strings.Join(chain, "/") == removeKey {
							delete(d, key)
						}
					}

					if value, ok := v.(map[interface{}]interface{}); ok {
						checkChain(value, chain)
					}
					if value, ok := v.([]interface{}); ok {
						d[k] = checkSliceChain(value, append(chain, "[]"))
					}

					chain = chain[:len(chain)-1] // we're done with this key, remove it from the chain
				}
			}
		}
	}

	return s
}

func loadVariant() {
	variant := ""
	flag.StringVar(&variant, "variant", "", "variant of remove rules")
	flag.Parse()

	// filter-crd is also able to be used without variant which should produce the same output again
	// this section used to have multiple variants for legacy releases, this has been removed now
	// TODO: ultimately we should find a we should find a way to remove the Helm specific labels
	// without using this hack
	if variant == "no-helm" {
		removeKeys = []string{
			"metadata/labels/app.kubernetes.io/managed-by",
			"metadata/labels/helm.sh/chart",
			"spec/template/metadata/labels/app.kubernetes.io/managed-by",
			"spec/template/metadata/labels/helm.sh/chart",
		}
	}
}
