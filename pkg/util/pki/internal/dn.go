/*
Copyright 2020 The cert-manager Authors.

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

// Initial implementation is based on https://github.com/go-ldap/ldap/blob/25b14db0ff3f3c0e927771e4441cdf61400367fd/dn.go

package internal

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type AttributeTypeAndValue struct {
	Type  string
	Value any
}

type RelativeDN struct {
	Attributes []AttributeTypeAndValue
}

// ParseDN parses a string representation of a Distinguished Name (DN) into a
// slice of RelativeDNs. The input string should be in the format of a DN as
// defined in RFC 4514 and RFC 2253. The input string is split into Relative
// Distinguished Names (RDNs) by the ',' or ';' character. Each RDN is then
// split into AttributeType and AttributeValue pairs by the '=' character.
// Multiple Attributes in an RDN are separated by the '+' character. The input
// string may contain escaped characters using the '\' character. The following
// characters can be escaped: ' ', '"', '#', '+', ',', ';', '<', '=', '>', and '\'.
// The escaped character is removed and the following character is treated as
// a literal. If the input string contains hex-encoded characters of the form '\XX'
// where XX is a two-character hexadecimal number, the hex-encoded character is
// replaced with the decoded character. If the value of an AttributeValue starts
// with a '#' character, the value is assumed to be hex-encoded asn1 DER and is
// decoded before being added to the RelativeDN.
func ParseDN(str string) ([]RelativeDN, error) {
	if len(strings.TrimSpace(str)) == 0 {
		return nil, nil
	}

	var rdns []RelativeDN

	var attribute AttributeTypeAndValue
	var addAttribute func(last bool)
	var setType func(string) error
	var setValue func(string) error
	{
		rdn := RelativeDN{}
		// addAttribute is a closure that adds the current attribute to the
		// current RDN and resets the attribute for the next one. If last is
		// true, it also adds the current RDN to the list of RDNs and resets
		// the RDN for the next one.
		addAttribute = func(last bool) {
			rdn.Attributes = append(rdn.Attributes, attribute)
			attribute = AttributeTypeAndValue{}
			if last {
				rdns = append(rdns, rdn)
				rdn = RelativeDN{}
			}
		}
		// setType is a closure that sets the type of the current attribute
		setType = func(s string) error {
			typeVal, err := decodeString(s)
			if err != nil {
				return err
			}
			attribute.Type = typeVal
			return nil
		}
		// setValue is a closure that sets the value of the current attribute
		setValue = func(s string) error {
			if len(s) > 0 && s[0] == '#' {
				valueVal, err := decodeEncodedString(s[1:])
				if err != nil {
					return err
				}
				attribute.Value = valueVal
				return nil
			} else {
				valueVal, err := decodeString(s)
				if err != nil {
					return err
				}
				attribute.Value = valueVal
				return nil
			}
		}
	}

	valueStart := 0
	escaping := false
	for pos, char := range str {
		switch {
		case escaping:
			escaping = false
		case char == '\\':
			escaping = true
		case char == '=' && len(attribute.Type) == 0:
			if err := setType(str[valueStart:pos]); err != nil {
				return nil, err
			}
			valueStart = pos + 1
		case char == ',' || char == '+' || char == ';':
			if len(attribute.Type) == 0 {
				return nil, errors.New("incomplete type, value pair")
			}
			if err := setValue(str[valueStart:pos]); err != nil {
				return nil, err
			}
			valueStart = pos + 1

			// The attribute value is complete, add it to the RDN
			// only go to the next RDN if the separator is a comma
			// or semicolon
			addAttribute(char == ',' || char == ';')
		}
	}

	if len(attribute.Type) == 0 {
		return nil, errors.New("DN ended with incomplete type, value pair")
	}
	if err := setValue(str[valueStart:]); err != nil {
		return nil, err
	}

	// The attribute value is complete, add it to the RDN
	addAttribute(true)

	return rdns, nil
}

// If the string starts with a #, it's a hex-encoded DER value
// This function decodes the value after the # and returns the decoded value.
func decodeEncodedString(inVal string) (any, error) {
	decoded, err := hex.DecodeString(inVal)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex-encoded string: %s", err)
	}

	var rawValue asn1.RawValue
	rest, err := asn1.Unmarshal(decoded, &rawValue)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal hex-encoded string: %s", err)
	}
	if len(rest) != 0 {
		return "", errors.New("trailing data after unmarshalling hex-encoded string")
	}

	return rawValue, nil
}

// Remove leading and trailing spaces from the attribute type and value
// and unescape any escaped characters in these fields
func decodeString(inVal string) (string, error) {
	s := []rune(strings.TrimSpace(inVal))
	// Re-add the trailing space if the last character was an escape character
	if (len(s) > 0 && s[len(s)-1] == '\\') && (len(inVal) > 0 && inVal[len(inVal)-1] == ' ') {
		s = append(s, ' ')
	}

	builder := strings.Builder{}
	for i := 0; i < len(s); i++ {
		r := s[i]

		// If the character is not an escape character, just add it to the
		// builder and continue
		if r != '\\' {
			builder.WriteRune(r)
			continue
		}

		// If the escape character is the last character, it's a corrupted
		// escaped character
		if i+1 >= len(s) {
			return "", errors.New("got corrupted escaped character")
		}

		// If the escaped character is a special character, just add it to
		// the builder and continue
		switch s[i+1] {
		case ' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\':
			builder.WriteRune(s[i+1])
			i++
			continue
		}

		// If the escaped character is not a special character, it should
		// be a hex-encoded character of the form \XX if it's not at least
		// two characters long, it's a corrupted escaped character
		if i+2 >= len(s) {
			return "", errors.New("failed to decode escaped character: encoding/hex: invalid byte: " + string(s[i+1]))
		}

		// Get the runes for the two characters after the escape character
		// and convert them to a byte slice
		xx := []byte(string(s[i+1 : i+3]))

		// If the two runes are not hex characters and result in more than
		// two bytes when converted to a byte slice, it's a corrupted
		// escaped character
		if len(xx) != 2 {
			return "", errors.New("failed to decode escaped character: encoding/hex: invalid byte: " + string(xx))
		}

		// Decode the hex-encoded character and add it to the builder
		dst := []byte{0}
		if n, err := hex.Decode(dst, xx); err != nil {
			return "", errors.New("failed to decode escaped character: " + err.Error())
		} else if n != 1 {
			return "", fmt.Errorf("failed to decode escaped character: encoding/hex: expected 1 byte when un-escaping, got %d", n)
		}

		builder.WriteByte(dst[0])
		i += 2
	}

	return builder.String(), nil
}
