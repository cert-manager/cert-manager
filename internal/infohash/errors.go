/*
Copyright 2022 The cert-manager Authors.

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

package infohash

import "fmt"

// ErrInvalidHash is returned by Compare if the hash is invalid.
var ErrInvalidHash = fmt.Errorf("invalid hash")

// FieldChangedError is returned by Compare if the hashes indicate
// that the fields have changed.
type FieldChangedError struct {
	// Change contains the field that changed and its new value.
	// If we do know which field changed (eg. because there were
	// multiple changes), Change will be nil.
	Change *FieldChange
}

type FieldChange struct {
	FieldName string
	NewValue  interface{}
}

func (e FieldChangedError) Error() string {
	if e.Change == nil {
		return "field changed"
	}

	newValue := prettyPrintConfigForHash.Sprintf("%#v", e.Change.NewValue)

	return "field changed: " + e.Change.FieldName + " to " + newValue
}
