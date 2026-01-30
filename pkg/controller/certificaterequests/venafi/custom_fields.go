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
	"encoding/json"
	"sort"

	"github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/api"
)

func parseCustomFieldAnnotation(annotation string) ([]api.CustomField, error) {
	var fields []api.CustomField
	err := json.Unmarshal([]byte(annotation), &fields)
	if err != nil {
		return nil, err
	}
	return fields, nil
}

func mergeCustomFields(global, override []api.CustomField) []api.CustomField {
	mergedMap := make(map[string]api.CustomField)
	for _, g := range global {
		mergedMap[g.Name] = g
	}

	for _, o := range override {
		mergedMap[o.Name] = o
	}

	merged := make([]api.CustomField, 0, len(mergedMap))
	for _, v := range mergedMap {
		merged = append(merged, v)
	}
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].Name < merged[j].Name
	})

	return merged
}
