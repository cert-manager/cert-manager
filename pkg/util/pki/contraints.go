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

package pki

// PathLenFromValue returns -1 and false if the given value is nil.
// Returns the underlying int value and value == 0 otherwise.
func PathLenFromValue(pathLen *int) (int, bool) {
	if pathLen == nil {
		return -1, false
	}

	return *pathLen, *pathLen == 0
}
