/*
Copyright 2024 The cert-manager Authors.

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
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMustParseRDN(t *testing.T) {
	subject := "SERIALNUMBER=42, L=some-locality, ST=some-state-or-province, STREET=some-street, CN=foo-long.com, OU=FooLong, OU=Barq, OU=Baz, OU=Dept., O=Corp., C=US+123.544.555= A Test Value "
	rdnSeq, err := UnmarshalSubjectStringToRDNSequence(subject)
	if err != nil {
		t.Fatal(err)
	}

	expectedRdnSeq :=
		pkix.RDNSequence{
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Country, Value: "US"},
				{Type: asn1.ObjectIdentifier{123, 544, 555}, Value: "A Test Value"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Organization, Value: "Corp."},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Dept."},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Baz"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Barq"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "FooLong"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.CommonName, Value: "foo-long.com"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.StreetAddress, Value: "some-street"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Province, Value: "some-state-or-province"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Locality, Value: "some-locality"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.SerialNumber, Value: "42"},
			},
		}

	assert.Equal(t, expectedRdnSeq, rdnSeq)
}

func TestMustKeepOrderInRawDerBytes(t *testing.T) {
	subject := "CN=foo-long.com,OU=FooLong,OU=Barq,OU=Baz,OU=Dept.,O=Corp.,C=US"
	rdnSeq, err := UnmarshalSubjectStringToRDNSequence(subject)
	if err != nil {
		t.Fatal(err)
	}

	expectedRdnSeq :=
		pkix.RDNSequence{
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Country, Value: "US"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.Organization, Value: "Corp."},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Dept."},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Baz"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "Barq"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.OrganizationalUnit, Value: "FooLong"},
			},
			[]pkix.AttributeTypeAndValue{
				{Type: OIDConstants.CommonName, Value: "foo-long.com"},
			},
		}

	assert.Equal(t, expectedRdnSeq, rdnSeq)
	assert.Equal(t, subject, rdnSeq.String())
}

func TestShouldFailForHexDER(t *testing.T) {
	_, err := UnmarshalSubjectStringToRDNSequence("DF=#6666666666665006838820013100000746939546349182108463491821809FBFFFFFFFFF")
	if err == nil {
		t.Fatal("expected error, but got none")
	}

	assert.Contains(t, err.Error(), "failed to decode BER encoding: unexpected EOF")
}

// TestRoundTripRDNSequence tests a set of RDNSequences to ensure that they are
// the same after a round trip through String() and UnmarshalSubjectStringToRDNSequence().
func TestRoundTripRDNSequence(t *testing.T) {
	type testCase struct {
		name string
		rdn  pkix.RDNSequence
	}
	rdnSequences := []testCase{
		{
			name: "Simple RDNSequence",
			rdn: pkix.RDNSequence{
				[]pkix.AttributeTypeAndValue{
					{Type: OIDConstants.Organization, Value: "Corp."},
					{Type: OIDConstants.OrganizationalUnit, Value: "FooLong"},
				},
			},
		},
		{
			name: "Character Escaping",
			rdn: pkix.RDNSequence{
				[]pkix.AttributeTypeAndValue{
					{Type: OIDConstants.CommonName, Value: "foo-lon❤️\\g.com    "},
					{Type: OIDConstants.OrganizationalUnit, Value: "Foo===Long"},
					{Type: OIDConstants.OrganizationalUnit, Value: "Ba  rq"},
					{Type: OIDConstants.OrganizationalUnit, Value: "Baz"},
					{Type: OIDConstants.Country, Value: "fo\x00o-long.com"},
				},
				[]pkix.AttributeTypeAndValue{
					{Type: OIDConstants.Organization, Value: "C; orp."},
					{Type: OIDConstants.Country, Value: "US"},
				},
			},
		},
		{
			name: "Numeric OID",
			rdn: pkix.RDNSequence{
				[]pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{0, 5, 80, 99, 58962185}, Value: "String Value"},
				},
			},
		},
	}

	for _, tc := range rdnSequences {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			newRDNSeq, err := UnmarshalSubjectStringToRDNSequence(tc.rdn.String())
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, tc.rdn, newRDNSeq)
		})
	}
}

// FuzzRoundTripRDNSequence fuzzes the UnmarshalSubjectStringToRDNSequence function
// by generating random subject strings and for each successfully parsed RDNSequence,
// it will ensure that the round trip through String() and UnmarshalSubjectStringToRDNSequence()
// results in the same RDNSequence.
func FuzzRoundTripRDNSequence(f *testing.F) {
	f.Add("CN=foo-long.com,OU=FooLong,OU=Barq,OU=Baz,OU=Dept.,O=Corp.,C=US")
	f.Add("CN=foo-lon❤️\\,g.com,OU=Foo===Long,OU=Ba # rq,OU=Baz,O=C\\; orp.,C=US")
	f.Add("CN=fo\x00o-long.com,OU=\x04FooLong")
	f.Add("1.2.3.4=String Value")
	f.Add("1.3.6.1.4.1.1466.0=#04024869")

	f.Fuzz(func(t *testing.T, subjectString string) {
		t.Parallel()
		rdnSeq, err := UnmarshalSubjectStringToRDNSequence(subjectString)
		if err != nil {
			t.Skip()
		}

		hasSpecialChar := func(s string) bool {
			for _, char := range s {
				if char < ' ' || char > '~' {
					return true
				}
			}
			return false
		}
		for _, rdn := range rdnSeq {
			for _, tv := range rdn {
				// Skip if the Type was not recognized. The String() output will be
				// an invalid type, value pair with empty type, which will give a "DN ended with
				// an incomplete type, value pair" error when parsing.
				if tv.Type.String() == "" {
					t.Skip()
				}

				// Skip if the value contains special characters, as the String() function
				// will not escape them.
				if hasSpecialChar(tv.Value.(string)) {
					t.Skip()
				}
			}
		}

		newRDNSeq, err := UnmarshalSubjectStringToRDNSequence(rdnSeq.String())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, rdnSeq, newRDNSeq)
	})
}
