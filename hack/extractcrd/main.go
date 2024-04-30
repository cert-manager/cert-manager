/*
Copyright 2022 The cert-manager Authors.

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
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var docSeparatorRegexp = regexp.MustCompile(`\n---`)

func crdDecoder() runtime.Decoder {
	scheme := runtime.NewScheme()
	install.Install(scheme)

	cf := serializer.NewCodecFactory(scheme)
	return cf.UniversalDecoder()
}

func main() {
	logger := log.New(os.Stderr, "", 0)

	if len(os.Args) != 2 && len(os.Args) != 3 {
		logger.Printf("usage (filter all crds): %s <path-to-templated-resources.yaml>", os.Args[0])
		logger.Printf("usage (filter specific crd): %s <path-to-templated-resources.yaml> <name-of-crd>", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]
	var wantedCRDName *string
	if len(os.Args) == 3 {
		val := strings.ToLower(os.Args[2])
		wantedCRDName = &val
	}

	rawYAMLBytes, err := os.ReadFile(filename)
	if err != nil {
		logger.Printf("failed to read %q: %s", filename, err)
		os.Exit(1)
	}

	outWriter := os.Stdout

	docs := docSeparatorRegexp.Split(string(rawYAMLBytes), -1)

	decoder := crdDecoder()

	foundAny := false

	for _, doc := range docs {
		obj, _, err := decoder.Decode([]byte(doc), nil, nil)
		if err != nil {
			// could be any kind of resource, just ignore
			continue
		}

		crd, ok := obj.(*apiextensions.CustomResourceDefinition)
		if !ok {
			logger.Printf("doc was parsed without an error but wasn't a CRD, skipping")
			continue
		}

		doc = strings.TrimPrefix(doc, "---")
		doc = strings.TrimSpace(doc)

		if wantedCRDName == nil {
			if foundAny {
				fmt.Fprintln(outWriter, "---")
			}
			fmt.Fprintln(outWriter, doc)
			foundAny = true
			continue
		} else {
			crdName := strings.ToLower(crd.Spec.Names.Plural)
			if crdName == *wantedCRDName {
				fmt.Fprintln(outWriter, doc)
				return
			}
		}
	}

	if !foundAny {
		if wantedCRDName == nil {
			logger.Printf("couldn't find any CRDs in %q", filename)
		} else {
			logger.Printf("couldn't find a CRD with plural name %q in %q", *wantedCRDName, filename)
		}
		os.Exit(1)
	}
}
