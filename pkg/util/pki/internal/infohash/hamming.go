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

func calculateParityCodes(values []uint32) []uint32 {
	log2NumberOfFieldsPlusOne := log2OfXPlusOne(uint32(len(values)))
	parityCodes := make([]uint32, log2NumberOfFieldsPlusOne)

	for id, field := range values {
		for i := range parityCodes {
			if (id+1)&(1<<i) != 0 {
				parityCodes[i] ^= field
			}
		}
	}

	return parityCodes
}

func findErrorLocation(values []uint32, parityCodes []uint32) (int, error) {
	expectedCode := calculateParityCodes(values)
	var errorLocation uint32

	if len(parityCodes) != len(expectedCode) {
		return 0, ErrInvalidHash
	}

	for i := range parityCodes {
		if parityCodes[i] != expectedCode[i] {
			errorLocation |= 1 << i
		}
	}

	if errorLocation == 0 || errorLocation > uint32(len(values)) {
		// Could not find the error location (there is probably more than one error)
		return -1, nil
	}

	return int(errorLocation - 1), nil
}

func log2OfXPlusOne(x uint32) uint32 {
	var r uint32
	for x > 0 {
		x >>= 1
		r += 1
	}
	return r
}
