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

package testing

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-logr/logr"
)

// TestLogger is a logr.Logger that prints everything to t.Log.
type TestLogger struct {
	T          *testing.T
	name       string
	withValues []string
}

func (log TestLogger) Info(msg string, keysAndValues ...interface{}) {
	withValues := append([]string{}, log.withValues...)
	for i := 0; i < len(keysAndValues); i = i + 2 {
		withValues = append(withValues, fmt.Sprintf(`%s="%v"`, keysAndValues[i], keysAndValues[i+1]))
	}
	log.T.Logf("%s: %v", msg, strings.Join(withValues, " "))
}

func (TestLogger) Enabled() bool {
	return true
}

func (log TestLogger) Error(err error, msg string, args ...interface{}) {
	log.T.Logf("%s: %v: %v", msg, err, args)
}

func (log TestLogger) V(v int) logr.Logger {
	return log
}

func (log TestLogger) WithName(name string) logr.Logger {
	log.name = name
	return log
}

func (log TestLogger) WithValues(keysAndValues ...interface{}) logr.Logger {
	for i := 0; i < len(keysAndValues); i = i + 2 {
		log.withValues = append(log.withValues, fmt.Sprintf(`%s="%v"`, keysAndValues[i], keysAndValues[i+1]))
	}
	return log
}
