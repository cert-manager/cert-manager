/*
Copyright 2025 The cert-manager Authors.

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

package venafi

import (
	"testing"

	"github.com/stretchr/testify/assert"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/api"
)

func TestParseCustomFields(t *testing.T) {
	annotation := map[string]string{
		cmapi.VenafiCustomFieldsAnnotationKey: `[
                  {"name": "Authoriser Name", "value": "John Doe"},{"name": "Division", "value": "BU1"}
                ]`,
	}
	parsed, err := parseCustomFieldAnnotation(annotation[cmapi.VenafiCustomFieldsAnnotationKey])
	expected := []api.CustomField{
		{Name: "Authoriser Name", Value: "John Doe"},
		{Name: "Division", Value: "BU1"},
	}
	assert.NoError(t, err)
	assert.ElementsMatch(t, parsed, expected)

	brokenAnnotation := map[string]string{
		cmapi.VenafiCustomFieldsAnnotationKey: `[{"foo", "bar"}]`,
	}
	_, err = parseCustomFieldAnnotation(brokenAnnotation[cmapi.VenafiCustomFieldsAnnotationKey])
	assert.Error(t, err)
}

func TestMergeFields(t *testing.T) {
	globalFields := []api.CustomField{
		{Name: "Authoriser Name", Value: "John Doe"},
	}
	overrideFields := []api.CustomField{
		{Name: "Authoriser Name", Value: "Mary Jane"},
	}

	merged := mergeCustomFields(globalFields, overrideFields)
	assert.Equal(t, merged[0].Value, "Mary Jane")

	appendFields := []api.CustomField{
		{Name: "ServiceNow Application Code", Value: "CIXXXXX"},
	}
	appended := mergeCustomFields(globalFields, appendFields)
	assert.Len(t, appended, 2)
	assert.Contains(t, appended, appendFields[0])
}
