/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"reflect"
	"strings"

	"gopkg.in/yaml.v2"
)

var removeKeys = []string{}
var removeElementForValue = map[string]string{}
var singleCRDVersion = false

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

		if singleCRDVersion {
			spec, ok := d["spec"].(map[interface{}]interface{})
			if !ok {
				log.Fatal("Cannot read spec of CRD")
			}
			versions, ok := spec["versions"].([]interface{})
			if !ok {
				log.Fatal("Cannot read versions of CRD")
			}
			if len(versions) == 0 {
				log.Fatal("CRD versions length is 0")
			}
			if len(versions) > 1 {
				log.Fatal("Multiple CRD versions found while 1 is expected")
			}
			versionInfo, ok := versions[0].(map[interface{}]interface{})
			if !ok {
				log.Fatal("Cannot read version of CRD")
			}

			// move the schema to the root of the CRD as we only have 1 version specified
			if validations, exists := versionInfo["schema"]; exists {
				spec["validation"] = validations
				delete(versionInfo, "schema")
			}

		}

		fileOut, err := yaml.Marshal(d)
		if err != nil {
			log.Fatal("Error marshaling output: ", err)
		}

		output = append(output, string(fileOut))
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

					if value, ok := removeElementForValue[strings.Join(chain, "/")]; ok && value == v.(string) {
						s = removeFromSlice(s, d)
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

func removeFromSlice(s []interface{}, d map[interface{}]interface{}) []interface{} {
	newSlice := []interface{}{}

	for _, sliceVal := range s {
		if !reflect.DeepEqual(sliceVal, d) {
			newSlice = append(newSlice, sliceVal)
		}
	}

	s = newSlice
	return s
}

func loadVariant() {
	variant := ""
	flag.StringVar(&variant, "variant", "", "variant of remove rules")
	flag.Parse()

	if variant == "cert-manager-legacy" {
		// These are the keys that the script will remove for OpenShift 3 and older Kubernetes compatibility
		removeKeys = []string{
			"spec/preserveUnknownFields",
			"spec/validation/openAPIV3Schema/type",
			"spec/versions/[]/schema/openAPIV3Schema/type",
			"spec/conversion",
		}

		// this removed the whole version slice element if version name is `v1alpha3`
		removeElementForValue = map[string]string{
			"spec/versions/[]/name": "v1alpha3",
		}

		singleCRDVersion = true
	}
}
