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

package testutil

import (
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Diff is a wrapper around "github.com/google/go-cmp/cmp".Diff to compare two objects,
// taking into account that metav1.Time fields need special handling. This helps to avoid
// challenges with serializing/deserializing time fields in tests.
// The return value is also converted from cmp.Diff's string output to an error type.
func Diff(a any, b any, opts ...cmp.Option) error {
	allOpts := []cmp.Option{
		cmp.Transformer("metav1.Time", func(in metav1.Time) string {
			return in.Time.Format(time.RFC3339)
		}),
		cmp.Transformer("metav1.TimePtr", func(in *metav1.Time) *string {
			if in == nil {
				return nil
			}

			out := in.Time.Format(time.RFC3339)
			return &out
		}),
	}

	allOpts = append(allOpts, opts...)

	diff := cmp.Diff(
		a,
		b,
		allOpts...,
	)

	if diff != "" {
		return fmt.Errorf("unexpected difference between compared objects (-want +got):\n%s", diff)
	}

	return nil
}
