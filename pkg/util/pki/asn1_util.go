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
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ParseObjectIdentifier parses an object identifier from its string representation.
func ParseObjectIdentifier(oidString string) (oid asn1.ObjectIdentifier, err error) {
	if len(oidString) == 0 {
		return nil, errors.New("zero length OBJECT IDENTIFIER")
	}

	parts := strings.Split(oidString, ".")

	oid = make(asn1.ObjectIdentifier, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}

		oid = append(oid, value)
	}

	return oid, nil
}

type UniversalValue struct {
	Bytes           []byte
	Ia5String       string
	Utf8String      string
	PrintableString string
}

func MarshalUniversalValue(uv UniversalValue) ([]byte, error) {
	// Make sure we have only one field set
	{
		var count int
		if uv.Bytes != nil {
			count++
		}
		if uv.Ia5String != "" {
			count++
		}
		if uv.Utf8String != "" {
			count++
		}
		if uv.PrintableString != "" {
			count++
		}
		if count != 1 {
			return nil, fmt.Errorf("exactly one field must be set")
		}
	}

	var bytes []byte

	if uv.Bytes != nil {
		bytes = uv.Bytes
	} else {
		rawValue := asn1.RawValue{
			Class:      asn1.ClassUniversal,
			IsCompound: false,
		}
		switch {
		case uv.Ia5String != "":
			if err := isIA5String(uv.Ia5String); err != nil {
				return nil, errors.New("asn1: invalid IA5 string")
			}
			rawValue.Tag = asn1.TagIA5String
			rawValue.Bytes = []byte(uv.Ia5String)
		case uv.Utf8String != "":
			if !utf8.ValidString(uv.Utf8String) {
				return nil, errors.New("asn1: invalid UTF-8 string")
			}
			rawValue.Tag = asn1.TagUTF8String
			rawValue.Bytes = []byte(uv.Utf8String)
		case uv.PrintableString != "":
			if !isPrintable(uv.PrintableString) {
				return nil, errors.New("asn1: invalid PrintableString string")
			}
			rawValue.Tag = asn1.TagPrintableString
			rawValue.Bytes = []byte(uv.PrintableString)
		}

		universalBytes, err := asn1.Marshal(rawValue)
		if err != nil {
			return nil, err
		}
		bytes = universalBytes
	}

	return bytes, nil
}

func isIA5String(s string) error {
	for _, r := range s {
		// Per RFC5280 "IA5String is limited to the set of ASCII characters"
		if r > unicode.MaxASCII {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}

// isPrintable reports whether the given b is in the ASN.1 PrintableString set.
// '*' and '&' are also allowed, reflecting existing practice.
func isPrintable(s string) bool {
	for _, b := range s {
		if 'a' <= b && b <= 'z' ||
			'A' <= b && b <= 'Z' ||
			'0' <= b && b <= '9' ||
			'\'' <= b && b <= ')' ||
			'+' <= b && b <= '/' ||
			b == ' ' ||
			b == ':' ||
			b == '=' ||
			b == '?' ||
			// This is technically not allowed in a PrintableString.
			// However, x509 certificates with wildcard strings don't
			// always use the correct string type so we permit it.
			b == '*' ||
			// This is not technically allowed either. However, not
			// only is it relatively common, but there are also a
			// handful of CA certificates that contain it. At least
			// one of which will not expire until 2027.
			b == '&' {
			continue
		}

		return false
	}

	return true
}

func UnmarshalUniversalValue(rawValue asn1.RawValue) (UniversalValue, error) {
	var uv UniversalValue

	if rawValue.FullBytes == nil {
		fullBytes, err := asn1.Marshal(rawValue)
		if err != nil {
			return uv, err
		}
		rawValue.FullBytes = fullBytes
	}

	var rest []byte
	var err error
	if rawValue.Tag == asn1.TagIA5String {
		rest, err = asn1.UnmarshalWithParams(rawValue.FullBytes, &uv.Ia5String, "ia5")
	} else if rawValue.Tag == asn1.TagUTF8String {
		rest, err = asn1.UnmarshalWithParams(rawValue.FullBytes, &uv.Utf8String, "utf8")
	} else if rawValue.Tag == asn1.TagPrintableString {
		rest, err = asn1.UnmarshalWithParams(rawValue.FullBytes, &uv.PrintableString, "printable")
	} else {
		uv.Bytes = rawValue.FullBytes
	}
	if err != nil {
		return uv, err
	}
	if len(rest) != 0 {
		return uv, fmt.Errorf("trailing data")
	}

	return uv, nil
}