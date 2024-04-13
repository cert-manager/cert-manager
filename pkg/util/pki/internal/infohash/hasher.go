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
	"hash/fnv"
	"io"
	"reflect"

	"github.com/davecgh/go-spew/spew"
)

func New() Hasher {
	return &hasher{}
}

type hasher struct {
	fields []field
}

var _ Hasher = &hasher{}

type field struct {
	name         string
	value        interface{}
	defaultValue interface{}
}

func (h *hasher) WriteFieldWithDefault(name string, value interface{}, defaultValue interface{}) Hasher {
	// Make sure that the default value is always the same type as the value.
	if reflect.TypeOf(value) != reflect.TypeOf(defaultValue) {
		panic("PROGRAMMING ERROR: The default value must be the same type as the value")
	}

	// Make sure we don't add too many fields. The length of the fields slice is stored in a uint16.
	if len(h.fields) >= 65535 {
		panic("PROGRAMMING ERROR: too many fields passed to checkHash, max is 65535")
	}

	h.fields = append(h.fields, field{name, value, defaultValue})
	return h
}

func (h *hasher) WriteField(name string, value interface{}) Hasher {
	return h.WriteFieldWithDefault(name, value, reflect.Zero(reflect.TypeOf(value)).Interface())
}

func (h *hasher) Sum() ([]byte, error) {
	fullHash, fieldHashes, err := calculateAllHashes(h.fields)
	if err != nil {
		return nil, err
	}

	fieldCount := uint16(len(fieldHashes))
	fieldCountBytes := uint16ToSlice(fieldCount)

	fullHashBytes := uint64ToSlice(fullHash)

	parityCodes := calculateParityCodes(fieldHashes)
	parityCodesBytes := uint32SliceToByteSlice(parityCodes)

	bytes := make([]byte, 0, len(fieldCountBytes)+len(fullHashBytes)+len(parityCodesBytes))
	bytes = append(bytes, fieldCountBytes...)
	bytes = append(bytes, fullHashBytes...)
	bytes = append(bytes, parityCodesBytes...)
	return bytes, nil
}

func (h *hasher) Compare(hash []byte) error {
	// Check that the hash is at least 10 bytes long.
	// 2 bytes for the field count, 8 bytes for the full hash.
	if len(hash) < 10 {
		return ErrInvalidHash
	}

	// Check that the parity codes are a multiple of 4 bytes.
	if len(hash[10:])%4 != 0 {
		return ErrInvalidHash
	}

	fieldCount := uint16FromSlice(hash)

	if len(h.fields) < int(fieldCount) {
		return ErrInvalidHash
	}

	// Check that all the new field values are equal to the default values.
	nonHashedFields := h.fields[fieldCount:]
	if len(nonHashedFields) > 0 {
		fullHasher1 := fnv.New64a()
		fullHasher2 := fnv.New64a()
		for _, info := range nonHashedFields {
			fullHasher1.Reset()
			fullHasher2.Reset()

			if err := stablePrint(fullHasher1, info.value); err != nil {
				return err
			}

			if err := stablePrint(fullHasher2, info.defaultValue); err != nil {
				return err
			}

			if fullHasher1.Sum64() != fullHasher2.Sum64() {
				return FieldChangedError{
					Change: &FieldChange{
						FieldName: info.name,
						NewValue:  info.value,
					},
				}
			}
		}
	}

	// Check that all the fields in the hash are equal to the fields in the struct.
	hashedFields := h.fields[:fieldCount]

	objFullHash, objFieldHashes, err := calculateAllHashes(hashedFields)
	if err != nil {
		return err
	}

	fullHash := uint64FromSlice(hash[2:10])
	if objFullHash == fullHash {
		// Happy path, no fields have changed.
		return nil
	}

	parityCodes := uint32SliceFromByteSlice(hash[10:])
	location, err := findErrorLocation(objFieldHashes, parityCodes)
	if err != nil {
		return err
	}

	if location > 0 {
		return FieldChangedError{
			Change: &FieldChange{
				FieldName: hashedFields[location].name,
				NewValue:  hashedFields[location].value,
			},
		}
	}

	return FieldChangedError{}
}

func calculateAllHashes(fields []field) (uint64, []uint32, error) {
	fieldHashes := make([]uint32, 0, len(fields))

	fullHasher := fnv.New64a()
	fieldHasher := fnv.New32a()
	multiWriter := io.MultiWriter(fullHasher, fieldHasher)

	for _, info := range fields {
		fieldHasher.Reset()

		if err := stablePrint(multiWriter, info.value); err != nil {
			return 0, nil, err
		}

		fieldHashes = append(fieldHashes, fieldHasher.Sum32())
	}

	return fullHasher.Sum64(), fieldHashes, nil
}

func stablePrint(writer io.Writer, v interface{}) error {
	_, err := prettyPrintConfigForHash.Fprintf(writer, "%#v", v)
	return err
}

// The config MUST NOT be changed because that could change the result of a hash operation
// Based on: https://github.com/kubernetes/kubernetes/blob/f7cb8a5e8a860df643e143cde54d34080372b771/staging/src/k8s.io/apimachinery/pkg/util/dump/dump.go#L47
var prettyPrintConfigForHash = &spew.ConfigState{
	Indent:                  " ",
	SortKeys:                true,
	DisableMethods:          true,
	SpewKeys:                true,
	DisablePointerAddresses: true,
	DisableCapacities:       true,
}
