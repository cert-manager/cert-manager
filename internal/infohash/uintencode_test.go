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
	"bytes"
	"slices"
	"testing"
)

func TestUint16FromSlice(t *testing.T) {
	if uint16FromSlice([]byte{0x12, 0x34}) != 0x1234 {
		t.Error("uint16FromSlice failed")
	}
}

func TestUint16ToSlice(t *testing.T) {
	if !bytes.Equal(uint16ToSlice(0x1234), []byte{0x12, 0x34}) {
		t.Error("uint16ToSlice failed")
	}
}

func TestUint64FromSlice(t *testing.T) {
	if uint64FromSlice([]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}) != 0x123456789abcdef0 {
		t.Error("uint64FromSlice failed")
	}
}

func TestUint64ToSlice(t *testing.T) {
	if !bytes.Equal(uint64ToSlice(0x123456789abcdef0), []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}) {
		t.Error("uint64ToSlice failed")
	}
}

func TestUint32SliceFromByteSlice(t *testing.T) {
	if !slices.Equal(uint32SliceFromByteSlice([]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}), []uint32{0x12345678, 0x9abcdef0}) {
		t.Error("uint32SliceFromByteSlice failed")
	}
}

func TestUint32SliceToByteSlice(t *testing.T) {
	if !bytes.Equal(uint32SliceToByteSlice([]uint32{0x12345678, 0x9abcdef0}), []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}) {
		t.Error("uint32SliceToByteSlice failed")
	}
}
