/*
Copyright 2026 The cert-manager Authors.
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
package baker

import (
	"fmt"
	"strings"
)

type EnterpriseOptions struct {
	Registry  string
	Namespace string
	FIPS      bool
	AllowEU   bool
}

func RewriteEnterpriseImages(inputPath string, outputPath string, opts EnterpriseOptions) error {
	if opts.Registry != "" && strings.Contains(opts.Registry, "venafi.eu") && !opts.AllowEU {
		return fmt.Errorf("enterprise registry %q requires --allow-eu", opts.Registry)
	}
	return modifyValuesYAML(inputPath, outputPath, func(values map[string]any) (map[string]any, error) {
		if opts.Registry != "" {
			values["imageRegistry"] = opts.Registry
		}
		if opts.Namespace != "" {
			values["imageNamespace"] = opts.Namespace
		}
		if !opts.FIPS {
			return values, nil
		}
		newValues, err := allNestedStringValues(values, nil, func(path []string, value string) (string, error) {
			if len(path) < 2 || path[len(path)-2] != "image" || path[len(path)-1] != "name" {
				return value, nil
			}
			if value == "" || strings.HasSuffix(value, "-fips") {
				return value, nil
			}
			return value + "-fips", nil
		})
		if err != nil {
			return nil, err
		}
		return newValues.(map[string]any), nil
	})
}
