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

// Initial implementation is based on https://github.com/go-ldap/ldap/blob/25b14db0ff3f3c0e927771e4441cdf61400367fd/dn_test.go

package internal

import (
	"encoding/asn1"
	"reflect"
	"testing"
)

func TestSuccessfulDNParsing(t *testing.T) {
	testcases := map[string][]RelativeDN{
		"": nil,
		"cn=Jim\\2C \\22Hasse Hö\\22 Hansson!,dc=dummy,dc=com": {
			{[]AttributeTypeAndValue{{"cn", "Jim, \"Hasse Hö\" Hansson!"}}},
			{[]AttributeTypeAndValue{{"dc", "dummy"}}},
			{[]AttributeTypeAndValue{{"dc", "com"}}},
		},
		"UID=jsmith,DC=example,DC=net": {
			{[]AttributeTypeAndValue{{"UID", "jsmith"}}},
			{[]AttributeTypeAndValue{{"DC", "example"}}},
			{[]AttributeTypeAndValue{{"DC", "net"}}},
		},
		"OU=Sales+CN=J. Smith,DC=example,DC=net": {
			{[]AttributeTypeAndValue{
				{"OU", "Sales"},
				{"CN", "J. Smith"},
			}},
			{[]AttributeTypeAndValue{{"DC", "example"}}},
			{[]AttributeTypeAndValue{{"DC", "net"}}},
		},
		"CN=Lu\\C4\\8Di\\C4\\87": {
			{[]AttributeTypeAndValue{{"CN", "Lučić"}}},
		},
		"  CN  =  Lu\\C4\\8Di\\C4\\87  ": {
			{[]AttributeTypeAndValue{{"CN", "Lučić"}}},
		},
		`   A   =   1   ,   B   =   2   `: {
			{[]AttributeTypeAndValue{{"A", "1"}}},
			{[]AttributeTypeAndValue{{"B", "2"}}},
		},
		`   A   =   1   +   B   =   2   `: {
			{[]AttributeTypeAndValue{
				{"A", "1"},
				{"B", "2"},
			}},
		},
		`   \ \ A\ \    =   \ \ 1\ \    ,   \ \ B\ \    =   \ \ 2\ \    `: {
			{[]AttributeTypeAndValue{{"  A  ", "  1  "}}},
			{[]AttributeTypeAndValue{{"  B  ", "  2  "}}},
		},
		`   \ \ A\ \    =   \ \ 1\ \    +   \ \ B\ \    =   \ \ 2\ \    `: {
			{[]AttributeTypeAndValue{
				{"  A  ", "  1  "},
				{"  B  ", "  2  "},
			}},
		},
		`cn=john.doe;dc=example,dc=net`: {
			{[]AttributeTypeAndValue{{"cn", "john.doe"}}},
			{[]AttributeTypeAndValue{{"dc", "example"}}},
			{[]AttributeTypeAndValue{{"dc", "net"}}},
		},
		`cn=⭐;dc=❤️=\==,dc=❤️\\`: {
			{[]AttributeTypeAndValue{{"cn", "⭐"}}},
			{[]AttributeTypeAndValue{{"dc", "❤️==="}}},
			{[]AttributeTypeAndValue{{"dc", "❤️\\"}}},
		},

		// Escaped `;` should not be treated as RDN
		`cn=john.doe\;weird name,dc=example,dc=net`: {
			{[]AttributeTypeAndValue{{"cn", "john.doe;weird name"}}},
			{[]AttributeTypeAndValue{{"dc", "example"}}},
			{[]AttributeTypeAndValue{{"dc", "net"}}},
		},
		`cn=ZXhhbXBsZVRleHQ=,dc=dummy,dc=com`: {
			{[]AttributeTypeAndValue{{"cn", "ZXhhbXBsZVRleHQ="}}},
			{[]AttributeTypeAndValue{{"dc", "dummy"}}},
			{[]AttributeTypeAndValue{{"dc", "com"}}},
		},
		`1.3.6.1.4.1.1466.0=test`: {
			{[]AttributeTypeAndValue{{"1.3.6.1.4.1.1466.0", "test"}}},
		},
		`1=#04024869`: {
			{[]AttributeTypeAndValue{{"1", asn1.RawValue{
				Tag: 4, Class: 0,
				IsCompound: false,
				Bytes:      []byte{0x48, 0x69},
				FullBytes:  []byte{0x04, 0x02, 0x48, 0x69},
			}}}},
		},
		`1.3.6.1.4.1.1466.0=#04024869`: {
			{[]AttributeTypeAndValue{{"1.3.6.1.4.1.1466.0", asn1.RawValue{
				Tag: 4, Class: 0,
				IsCompound: false,
				Bytes:      []byte{0x48, 0x69},
				FullBytes:  []byte{0x04, 0x02, 0x48, 0x69},
			}}}},
		},
		`1.3.6.1.4.1.1466.0=#04024869,DC=net`: {
			{[]AttributeTypeAndValue{{"1.3.6.1.4.1.1466.0", asn1.RawValue{
				Tag: 4, Class: 0,
				IsCompound: false,
				Bytes:      []byte{0x48, 0x69},
				FullBytes:  []byte{0x04, 0x02, 0x48, 0x69},
			}}}},
			{[]AttributeTypeAndValue{{"DC", "net"}}},
		},
	}

	for test, answer := range testcases {
		t.Log("Testing:", test)

		dn, err := ParseDN(test)
		if err != nil {
			t.Fatal(err)
			continue
		}
		if !reflect.DeepEqual(dn, answer) {
			t.Errorf("Parsed DN %s is not equal to the expected structure", test)
			t.Logf("Expected:")
			for _, rdn := range answer {
				for _, attribs := range rdn.Attributes {
					t.Logf("#%v\n", attribs)
				}
			}
			t.Logf("Actual:")
			for _, rdn := range dn {
				for _, attribs := range rdn.Attributes {
					t.Logf("#%v\n", attribs)
				}
			}
		}
	}
}

func TestErrorDNParsing(t *testing.T) {
	testcases := map[string]string{
		"*":                         "DN ended with incomplete type, value pair",
		"cn=Jim\\0Test":             "failed to decode escaped character: encoding/hex: invalid byte: U+0054 'T'",
		"cn=Jim\\0":                 "failed to decode escaped character: encoding/hex: invalid byte: 0",
		"DC=example,=net":           "DN ended with incomplete type, value pair",
		"test,DC=example,DC=com":    "incomplete type, value pair",
		"=test,DC=example,DC=com":   "incomplete type, value pair",
		"1.3.6.1.4.1.1466.0=test+":  "DN ended with incomplete type, value pair",
		`1.3.6.1.4.1.1466.0=test;`:  "DN ended with incomplete type, value pair",
		"1.3.6.1.4.1.1466.0=test+,": "incomplete type, value pair",
		"1=#0402486":                "failed to decode hex-encoded string: encoding/hex: odd length hex string",
		"DF=#6666666666665006838820013100000746939546349182108463491821809FBFFFFFFFFF": "failed to unmarshal hex-encoded string: asn1: syntax error: data truncated",
	}

	for test, answer := range testcases {
		_, err := ParseDN(test)
		if err == nil {
			t.Errorf("Expected %s to fail parsing but succeeded\n", test)
		} else if err.Error() != answer {
			t.Errorf("Unexpected error on %s:\n%s\nvs.\n%s\n", test, answer, err.Error())
		}
	}
}

func BenchmarkParseSubject(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := ParseDN("DF=#6666666666665006838820013100000746939546349182108463491821809FBFFFFFFFFF")
		if err == nil {
			b.Fatal("expected error, but got none")
		}
	}
}
