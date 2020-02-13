/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package install

import (
	"fmt"
	"testing"

	crdfuzz "github.com/munnerz/crd-schema-fuzz"

	"github.com/jetstack/cert-manager/pkg/api"
	acmefuzzer "github.com/jetstack/cert-manager/pkg/internal/apis/acme/fuzzer"
)

func TestPruneTypes(t *testing.T) {
	crdfuzz.SchemaFuzzTestForCRDWithPath(t, api.Scheme, crdPath("orders"), acmefuzzer.Funcs)
	crdfuzz.SchemaFuzzTestForCRDWithPath(t, api.Scheme, crdPath("challenges"), acmefuzzer.Funcs)
}

func crdPath(s string) string {
	return fmt.Sprintf("../../../../../deploy/charts/cert-manager-crds/templates/%s.yaml", s)
}
