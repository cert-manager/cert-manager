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

package util

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestSetExitCode(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		expCode int
	}{
		{"Test context.Canceled", context.Canceled, 0},
		{"Test wrapped context.Canceled", fmt.Errorf("wrapped: %w", context.Canceled), 0},
		{"Test context.DeadlineExceeded", context.DeadlineExceeded, 124},
		{"Test wrapped context.DeadlineExceeded", fmt.Errorf("wrapped: %w", context.DeadlineExceeded), 124},
		{"Test error", errors.New("error"), 1},
		{"Test nil", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Every testExitCode call has to be run in its own test, because
			// it calls the test again filtered by the name of the subtest with
			// the variable BE_CRASHER=1.
			exitCode := testExitCode(t, func(t *testing.T) {
				SetExitCode(tt.err)

				_, complete := SetupExitHandler(context.Background(), AlwaysErrCode)
				complete()
			})

			if exitCode != tt.expCode {
				t.Errorf("Test %s: expected exit code %d, got %d", tt.name, tt.expCode, exitCode)
			}
		})
	}
}
