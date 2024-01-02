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

package test

import "k8s.io/apimachinery/pkg/util/rand"

type StringGenerator func(n int) string

// RandStringBytes generates a pseudo-random string of length `n`.
//
// Deprecated: Use k8s.io/apimachinery/pkg/util/rand#String instead
func RandStringBytes(n int) string {
	return rand.String(n)
}
