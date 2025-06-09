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
	"fmt"

	"k8s.io/apimachinery/pkg/util/rand"
)

// RandomSubdomain returns a new subdomain domain of the domain suffix.
// e.g., abcd.example.com.
func RandomSubdomain(domain string) string {
	return RandomSubdomainLength(domain, 5)
}

// RandomSubdomainLength returns a new subdomain domain of the domain suffix, where the
// subdomain has `length` number of characters.
// e.g., abcdefghij.example.com.
func RandomSubdomainLength(domain string, length int) string {
	return fmt.Sprintf("%s.%s", rand.String(length), domain)
}
