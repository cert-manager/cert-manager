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

package pki

import (
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMustParseRDN(t *testing.T) {
	subject := "SERIALNUMBER=42, L=some-locality, ST=some-state-or-province, STREET=some-street, CN=foo-long.com, OU=FooLong, OU=Barq, OU=Baz, OU=Dept., O=Corp., C=US"
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

	assert.Contains(t, err.Error(), "failed to unmarshal hex-encoded string: asn1: syntax error: data truncated")
}
