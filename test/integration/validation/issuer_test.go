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

package validation

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	"github.com/cert-manager/cert-manager/pkg/api"
)

var issuerGVK = schema.GroupVersionKind{
	Group:   "cert-manager.io",
	Version: "v1",
	Kind:    "Issuer",
}

// Regression tests to check Issuer configurations which are expected to pass
// the OpenAPI and webhook validation but which have been accidentally forbidden
// in the past by inconsistent use of validation annotations in the Go types or
// by incorrect logic in the validating webhook functions.
func TestValidationIssuer(t *testing.T) {
	yamlFile := "files/issuers.valid.yaml"
	yamlBytes, err := os.Open(yamlFile)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stop := framework.RunControlPlane(t, ctx)
	defer stop()

	framework.WaitForOpenAPIResourcesToBeLoaded(t, ctx, config, issuerGVK)

	cl, err := client.New(config, client.Options{Scheme: api.Scheme})
	require.NoError(t, err)

	dec := yaml.NewYAMLOrJSONDecoder(yamlBytes, 4096)
	documentIndex := 0
	for {
		obj := &unstructured.Unstructured{}
		err := dec.Decode(obj)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		name := fmt.Sprintf("%s:%d:%s/%s", yamlFile, documentIndex, obj.GetNamespace(), obj.GetName())
		t.Run(name, func(t *testing.T) {
			err = cl.Create(ctx, obj)
			assert.NoError(t, err)
		})
		documentIndex++
	}
}
