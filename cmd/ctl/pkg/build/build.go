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

package build

import (
	"bytes"
	"text/template"
)

// name is the build time configurable name of the build (name of the target
// binary name).
var name = "cmctl"

// Name returns the build name.
func Name() string {
	return name
}

// WithTemplate returns a string that has the build name templated out with the
// configured build name. Build name templates on '{{ .BuildName }}' variable.
func WithTemplate(str string) string {
	tmpl := template.Must(template.New("build-name").Parse(str))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ BuildName string }{name}); err != nil {
		// We panic here as it should never be possible that this template fails.
		panic(err)
	}
	return buf.String()
}
