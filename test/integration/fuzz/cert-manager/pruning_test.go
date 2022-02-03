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

package install

import (
	"testing"

	crdfuzz "github.com/munnerz/crd-schema-fuzz"

	cmfuzzer "github.com/cert-manager/cert-manager/internal/apis/certmanager/fuzzer"
	apitesting "github.com/cert-manager/cert-manager/internal/test/paths"
	"github.com/cert-manager/cert-manager/pkg/api"
)

func TestPruneTypes(t *testing.T) {
	crdfuzz.SchemaFuzzTestForCRDWithPath(t, api.Scheme, apitesting.PathForCRD(t, "certificates"), cmfuzzer.Funcs)
	crdfuzz.SchemaFuzzTestForCRDWithPath(t, api.Scheme, apitesting.PathForCRD(t, "certificaterequests"), cmfuzzer.Funcs)
	crdfuzz.SchemaFuzzTestForCRDWithPath(t, api.Scheme, apitesting.PathForCRD(t, "issuers"), cmfuzzer.Funcs)
	crdfuzz.SchemaFuzzTestForCRDWithPath(t, api.Scheme, apitesting.PathForCRD(t, "clusterissuers"), cmfuzzer.Funcs)
}
