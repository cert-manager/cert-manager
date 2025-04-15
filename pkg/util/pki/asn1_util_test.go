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
	"errors"
	"reflect"
	"testing"
)

func TestParseObjectIdentifier(t *testing.T) {
	testCases := []struct {
		oidString   string
		expectedOid asn1.ObjectIdentifier
		expectedErr error
	}{
		{
			oidString:   "1.2.3.4.5",
			expectedOid: asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			expectedErr: nil,
		},
		{
			oidString:   "1.2.840.113549.1.1.1",
			expectedOid: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
			expectedErr: nil,
		},
		{
			oidString:   "1.3.6.1.4.1.311.60.2.1.3",
			expectedOid: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3},
			expectedErr: nil,
		},
		{
			oidString:   ".",
			expectedOid: nil,
			expectedErr: errors.New("strconv.Atoi: parsing \"\": invalid syntax"),
		},
		{
			oidString:   ".555",
			expectedOid: nil,
			expectedErr: errors.New("strconv.Atoi: parsing \"\": invalid syntax"),
		},
		{
			oidString:   "555.",
			expectedOid: nil,
			expectedErr: errors.New("strconv.Atoi: parsing \"\": invalid syntax"),
		},
		{
			oidString:   "test.5",
			expectedOid: nil,
			expectedErr: errors.New("strconv.Atoi: parsing \"test\": invalid syntax"),
		},
	}

	for _, tc := range testCases {
		oid, err := ParseObjectIdentifier(tc.oidString)
		if err != nil {
			if tc.expectedErr == nil {
				t.Errorf("Unexpected error: %v", err)
			} else if err.Error() != tc.expectedErr.Error() {
				t.Errorf("Expected error: %v, got: %v", tc.expectedErr, err)
			}
		} else if !oid.Equal(tc.expectedOid) {
			t.Errorf("Expected OID: %v, got: %v", tc.expectedOid, oid)
		}
	}
}

func TestMarshalAndUnmarshalUniversalValue(t *testing.T) {
	testCases := []struct {
		name                string
		uv                  UniversalValue
		raw                 asn1.RawValue
		overrideRoundtripUv *UniversalValue
	}{
		{
			name: "Test with IA5String",
			uv: UniversalValue{
				IA5String: "test",
			},
			raw: asn1.RawValue{
				Bytes: []byte("test"),
				Class: asn1.ClassUniversal,
				Tag:   asn1.TagIA5String,
			},
		},
		{
			name: "Test with Utf8String",
			uv: UniversalValue{
				UTF8String: "test",
			},
			raw: asn1.RawValue{
				Bytes: []byte("test"),
				Class: asn1.ClassUniversal,
				Tag:   asn1.TagUTF8String,
			},
		},
		{
			name: "Test with PrintableString",
			uv: UniversalValue{
				PrintableString: "test",
			},
			raw: asn1.RawValue{
				Bytes: []byte("test"),
				Class: asn1.ClassUniversal,
				Tag:   asn1.TagPrintableString,
			},
		},
		{
			name: "Test with Bytes",
			uv: UniversalValue{
				// Ia5String byte array with value "test"
				// https://lapo.it/asn1js/#FgR0ZXN0
				Bytes: []byte{0x16, 0x04, 0x74, 0x65, 0x73, 0x74},
			},
			overrideRoundtripUv: &UniversalValue{
				IA5String: "test",
			},
			raw: asn1.RawValue{
				Bytes: []byte("test"),
				Class: asn1.ClassUniversal,
				Tag:   asn1.TagIA5String,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			{
				rawValue, err := MarshalUniversalValue(tc.uv)
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				// Calculate fullBytes
				fullBytes, err := asn1.Marshal(tc.raw)
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if !reflect.DeepEqual(rawValue, fullBytes) {
					t.Errorf("Expected rawValue: %v, got: %v", fullBytes, rawValue)
				}
			}

			{
				uv, err := UnmarshalUniversalValue(tc.raw)
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				targetUv := tc.uv
				if tc.overrideRoundtripUv != nil {
					targetUv = *tc.overrideRoundtripUv
				}
				if !reflect.DeepEqual(uv, targetUv) {
					t.Errorf("Expected uv: %v, got: %v", targetUv, uv)
				}
			}
		})
	}
}

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
