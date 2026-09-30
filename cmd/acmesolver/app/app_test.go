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

package app

import (
	"testing"
)

// The logging options are built and applied in PreRunE, so they only do
// anything if they are also registered on the flag set. They were dropped once
// before, in c113a3ea ("remove logging flags from acmesolver"), which left
// ValidateAndApply acting on values nothing could set.
func TestLoggingFlagsAreRegistered(t *testing.T) {
	cmd := NewACMESolverCommand(t.Context())

	args := []string{"--logging-format=json", "-v=4", "--log-flush-frequency=1s"}
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}

	if err := cmd.PreRunE(cmd, nil); err != nil {
		t.Fatalf("PreRunE after parsing %v: %v", args, err)
	}

	for name, want := range map[string]string{
		"logging-format":      "json",
		"v":                   "4",
		"log-flush-frequency": "1s",
	} {
		flag := cmd.Flags().Lookup(name)
		if flag == nil {
			t.Errorf("flag %q is not registered", name)
			continue
		}
		if got := flag.Value.String(); got != want {
			t.Errorf("flag %q = %q, want %q", name, got, want)
		}
	}
}
