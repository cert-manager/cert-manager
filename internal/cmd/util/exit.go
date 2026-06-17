/*
Copyright 2021 The cert-manager Authors.

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
)

// SetExitCode sets the exit code to 1 if the error is not a context.Canceled error.
func SetExitCode(err error) {
	switch {
	case err == nil || errors.Is(err, context.Canceled):
		// If the context was canceled, we don't need to set the exit code
	case errors.Is(err, context.DeadlineExceeded):
		SetExitCodeValue(124) // Indicate that there was a timeout error
	default:
		SetExitCodeValue(1) // Indicate that there was an error
	}
}

// SetExitCode sets the exit code to 1 if the error is not a context.Canceled error.
func SetExitCodeValue(code int) {
	if code != 0 {
		select {
		case errorExitCodeChannel <- code:
		default:
			// The exit code has already been set to a non-zero value.
		}
	}
	// If the exit code is 0, we don't need to set the exit code
}
