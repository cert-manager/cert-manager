/*
Copyright 2023 The cert-manager Authors.

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

import (
	"encoding/asn1"
	"testing"
)

// Since we make use of the standard utf.ValidString
// we just do a sanity check to ensure it is used on Marshall/UnMarshal
func TestMarshalUTF8Validation(t *testing.T) {

	uv := UniversalValue{
		// Invalid utf8 byte sequence, string() just casts byte[] verbatim whereas "" causes compile error
		UTF8String: string([]byte{0xc3, 0x28}),
	}

	_, err := MarshalUniversalValue(uv)
	if err == nil {
		t.Error("Expected invalid UTF8 string to raise error")
	}

	inValidASN1UTF8 := asn1.RawValue{
		Tag:   asn1.TagUTF8String,
		Class: asn1.ClassUniversal,
		Bytes: []byte{0xe2, 0x82, 0x28}, // Another out of range utf8 byte sequence
	}

	_, err = UnmarshalUniversalValue(inValidASN1UTF8)
	if err == nil {
		t.Error("Expected invalid UTF8 asn1 value to raise error")
	}
}

func TestIsIA5String(t *testing.T) {
	ia5Strings := []string{
		"test",
		"1234",
		"!@#$",
		" ",
		"",
	}

	for _, ia5String := range ia5Strings {
		err := isIA5String(ia5String)

		if err != nil {
			t.Errorf("Expected IA5 string %q, got: %s", ia5String, err.Error())
		}
	}

	nonIA5Strings := []string{
		"中文", //nolint: gosmopolitan
	}

	for _, nonIA5String := range nonIA5Strings {
		err := isIA5String(nonIA5String)

		if err == nil {
			t.Errorf("Expected non-IA5 string error for %s, got: nil", nonIA5String)
		}
	}
}

func TestIsPrintable(t *testing.T) {
	printableStrings := []string{
		"test",
		"1234",
		"*AA:-)/?",
		" ",
		"",
		"Test*",
		"Test&",
	}

	for _, printableString := range printableStrings {
		isPrintable := isPrintable(printableString)

		if !isPrintable {
			t.Errorf("Expected printable string %q, got: %v", printableString, isPrintable)
		}
	}

	nonPrintableStrings := []string{
		"中文", //nolint: gosmopolitan
		"Test!",
		"Test@",
		"Test#",
		"Test%",
	}

	for _, nonPrintableString := range nonPrintableStrings {
		isPrintable := isPrintable(nonPrintableString)

		if isPrintable {
			t.Errorf("Expected non-printable string %q, got: %v", nonPrintableString, isPrintable)
		}
	}
}
