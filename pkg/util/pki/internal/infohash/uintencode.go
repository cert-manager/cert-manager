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

func uint16FromSlice(s []byte) uint16 {
	return uint16(0) |
		uint16(s[1])<<0 |
		uint16(s[0])<<8
}

func uint16ToSlice(i uint16) []byte {
	return []byte{
		byte(0xff & (i >> 8)),
		byte(0xff & (i >> 0)),
	}
}

func uint64FromSlice(s []byte) uint64 {
	return uint64(0) |
		uint64(s[7])<<0 |
		uint64(s[6])<<8 |
		uint64(s[5])<<16 |
		uint64(s[4])<<24 |
		uint64(s[3])<<32 |
		uint64(s[2])<<40 |
		uint64(s[1])<<48 |
		uint64(s[0])<<56
}

func uint64ToSlice(i uint64) []byte {
	return []byte{
		byte(0xff & (i >> 56)),
		byte(0xff & (i >> 48)),
		byte(0xff & (i >> 40)),
		byte(0xff & (i >> 32)),
		byte(0xff & (i >> 24)),
		byte(0xff & (i >> 16)),
		byte(0xff & (i >> 8)),
		byte(0xff & (i >> 0)),
	}
}

func uint32SliceFromByteSlice(s []byte) []uint32 {
	out := make([]uint32, len(s)/4)

	for i := range out {
		out[i] = uint32(s[i*4+3])<<0 |
			uint32(s[i*4+2])<<8 |
			uint32(s[i*4+1])<<16 |
			uint32(s[i*4+0])<<24
	}

	return out
}

func uint32SliceToByteSlice(i []uint32) []byte {
	out := make([]byte, len(i)*4)

	for j := range i {
		out[j*4+3] = byte(0xff & (i[j] >> 0))
		out[j*4+2] = byte(0xff & (i[j] >> 8))
		out[j*4+1] = byte(0xff & (i[j] >> 16))
		out[j*4+0] = byte(0xff & (i[j] >> 24))
	}

	return out
}
