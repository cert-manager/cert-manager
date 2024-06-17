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

import (
	"fmt"
	"math"
	"testing"
)

func TestHasher_SumAndCompare(t *testing.T) {
	tests := []struct {
		hash1    Hasher
		hash2    Hasher
		expected error
	}{
		{
			hash1:    New().WriteField("name1", "value1").WriteField("name2", 123),
			hash2:    New().WriteField("name1", "value1").WriteField("name2", 123),
			expected: nil,
		},
		{
			hash1:    New().WriteField("name1", "value1").WriteField("name2", 123),
			hash2:    New().WriteField("name1", "value1").WriteField("name2", 999),
			expected: FieldChangedError{Change: &FieldChange{FieldName: "name2", NewValue: 999}},
		},
		{
			// We allow fields to be renamed
			hash1:    New().WriteField("name1", "value1").WriteField("name2", 123),
			hash2:    New().WriteField("name1", "value1").WriteField("name3", 123),
			expected: nil,
		},
		{
			// We allow new fields to be added (compare will fail if the new field has a
			// different value than the default value)
			hash1:    New().WriteField("name1", "value1"),
			hash2:    New().WriteField("name1", "value1").WriteField("name2", 123),
			expected: FieldChangedError{Change: &FieldChange{FieldName: "name2", NewValue: 123}},
		},
		{
			// We allow new fields to be added (compare will succeed if the new field has the
			// same value as the default value)
			hash1:    New().WriteField("name1", "value1"),
			hash2:    New().WriteField("name1", "value1").WriteField("name2", 0),
			expected: nil,
		},

		{
			// We cannot detect a breaking default change, so we return nil.
			// WARNING: The user of the library should add unit tests to prevent this from happening.
			hash1:    New().WriteField("name1", "value1").WriteField("name2", 123),
			hash2:    New().WriteField("name1", "value1").WriteField("name2", 123),
			expected: nil,
		},
		{
			// We cannot detect a breaking change in the order of the fields, so we detect a changed field.
			// WARNING: The user of the library should add unit tests to prevent this from happening.
			hash1:    New().WriteField("name1", "value1").WriteField("name2", 123),
			hash2:    New().WriteField("name2", 123).WriteField("name1", "value1"),
			expected: FieldChangedError{},
		},
	}

	for id, test := range tests {
		test := test
		t.Run(fmt.Sprintf("test-%d", id+1), func(t *testing.T) {
			sum1, err := test.hash1.Sum()
			if err != nil {
				t.Fatalf("Expected nil, but got %v", err)
			}

			{
				err := test.hash2.Compare(sum1)
				// if err != nil and test.expected == nil, or if err == nil and test.expected != nil
				if (err != nil) != (test.expected != nil) {
					t.Fatalf("Expected %v, but got %v", test.expected, err)
				}

				// if err != nil and test.expected != nil
				if err != nil && err.Error() != test.expected.Error() {
					t.Fatalf("Expected %v, but got %v", test.expected, err)
				}
			}
		})
	}
}

func Test_Sum_Static(t *testing.T) {
	sum, err := New().
		WriteField("name1", "value1").
		WriteField("name2", 123).
		WriteField("name3", []byte{1, 2, 3}).
		WriteField("name4", 123.456).
		WriteField("name5", &struct{ aa int }{aa: 123}).
		Sum()
	if err != nil {
		t.Fatal(err)
	}

	hexSum := fmt.Sprintf("%x", sum)

	if hexSum != "0005b9e8e77d08167637824ae2b158f389cf41b41f87" {
		t.Fatalf("the hash has changed: %s", hexSum)
	}
}

func Test_Sum_Length(t *testing.T) {
	makeHashSum := func(i int) ([]byte, error) {
		hasher := New()
		for j := 0; j < i; j++ {
			hasher.WriteField(fmt.Sprintf("name%d", j), true)
		}
		return hasher.Sum()
	}

	for i := 0; i < 128; i++ {
		hash, err := makeHashSum(i)
		if err != nil {
			t.Fatal(err)
		}

		log2NumberOfFieldsPlusOne := int(math.Ceil(math.Log2(float64(i + 1))))

		if len(hash) != (16+64+log2NumberOfFieldsPlusOne*32)/8 {
			t.Fatalf("the hash length is wrong: %d != %d", len(hash), (64+log2NumberOfFieldsPlusOne*32)/8)
		}

		// hash length in case we would store a hash for each field:
		// 16 + 64 + 32 * (i - 1)
		hashForEachField := (16 + 64 + 32*math.Max(0, float64(i-1))) / 8

		t.Logf("number of fields: %d, infohash length: %d bytes, per-field hash length: %f bytes, relative change: %f %%", i, len(hash), hashForEachField, 100*(float64(len(hash))-hashForEachField)/hashForEachField)
	}
}
