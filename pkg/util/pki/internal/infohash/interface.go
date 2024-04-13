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

// Hasher can be used to hash a object.
type Hasher interface {
	// WriteField adds a field to the hash. Hashes can be extended
	// with new fields without invalidating existing hashes by writing
	// more fields, as long as the first N calls to WriteField have the same
	// value and defaultVlaue and are called in the same order, the longer hash
	// must than match the default values for the new fields.
	//
	// eg.
	// 	hashv1_sum := New().WriteField("a", "value").WriteField("b", 2).Sum()
	//  New().
	//    WriteField("a", "value").
	//    WriteField("b", 2).
	//    WriteFieldWithDefault("c", 3, 3).
	//    Compare(hashv1_sum) // == nil
	//  New().
	//    WriteField("a", "value").
	//    WriteField("b", 2).
	//    WriteFieldWithDefault("c", 4, 3).
	//    Compare(hashv1_sum) // == FieldChangedError{Change: &FieldChange{FieldName: "c", NewValue: 4}}
	//
	WriteFieldWithDefault(name string, value interface{}, defaultValue interface{}) Hasher

	// WriteField is similar to WriteFieldWithDefault, but it assumes the default
	// value is the zero value of the type of the field.
	WriteField(name string, value interface{}) Hasher

	// Sum returns the hash of the fields written so far. It tries to
	// be space efficient in case you want to know what field changed
	// and the object has 7+ fields, and long field values (longer than
	// 64 bits). Otherwise, storing the full object is probably more
	// space efficient for your usecase.
	// The output of Sum is a byte slice and can be compared with the
	// Compare function. Different byte slices can still represent the
	// same object, so it's important to use the Compare function instead
	// of doing a byte slice comparison.
	Sum() ([]byte, error)

	// Compare returns true if the written fields match the hash. It will
	// return true if the hashes contain the same fields, in the same order.
	// Even if you have written more fields than the provided hash, as long as
	// the extra fields match the default values, Compare will consider them
	// equal.
	// If the hashes are different, Compare will return a FieldChangedError.
	// This error contains the name of the field that was changed and the
	// new value. If more than one field was changed, Compare will return
	// a FieldChangedError with an empty Change field.
	Compare(hash []byte) error
}
