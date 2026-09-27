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

package options

import "fmt"

// Required returns msg as an error if *p is the zero value for T.
func Required[T comparable](p *T, msg string) error {
	var zero T

	if *p == zero {
		return fmt.Errorf("%s", msg)
	}

	return nil
}

// Unset returns msg as an error if *p is not the zero value for T.
func Unset[T comparable](p *T, msg string) error {
	var zero T

	if *p != zero {
		return fmt.Errorf("%s", msg)
	}

	return nil
}

// NotEmpty returns msg as an error if the slice at p is empty.
func NotEmpty[T comparable](p *[]T, msg string) error {
	if len(*p) == 0 {
		return fmt.Errorf("%s", msg)
	}

	return nil
}

// Default sets *p to v if *p is the zero value for T.
func Default[T comparable](p *T, v T) error {
	var zero T

	if *p == zero {
		*p = v
	}

	return nil
}

// DefaultFn sets *p to the result of fn if *p is the zero value for T.
func DefaultFn[T comparable](p *T, fn func() T) error {
	var zero T

	if *p == zero {
		*p = fn()
	}

	return nil
}

// True returns msg as an error if b is false.
func True[T ~bool](b T, msg string) error {
	if b {
		return nil
	}

	return fmt.Errorf("%s", msg)
}

// False returns msg as an error if b is true.
func False[T ~bool](b T, msg string) error {
	if !b {
		return nil
	}

	return fmt.Errorf("%s", msg)
}

// First returns the first non-nil error from the provided errors, or nil if
// all are nil. Unlike errors.Join, which collects all errors, First stops at
// the first failure. Use this when checks are mutually exclusive in intent but
// would otherwise both fire simultaneously with errors.Join.
func First(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
