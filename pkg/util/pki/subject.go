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
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

var OIDConstants = struct {
	Country            []int
	Organization       []int
	OrganizationalUnit []int
	CommonName         []int
	SerialNumber       []int
	Locality           []int
	Province           []int
	StreetAddress      []int
	DomainComponent    []int
	UniqueIdentifier   []int
}{
	Country:            []int{2, 5, 4, 6},
	Organization:       []int{2, 5, 4, 10},
	OrganizationalUnit: []int{2, 5, 4, 11},
	CommonName:         []int{2, 5, 4, 3},
	SerialNumber:       []int{2, 5, 4, 5},
	Locality:           []int{2, 5, 4, 7},
	Province:           []int{2, 5, 4, 8},
	StreetAddress:      []int{2, 5, 4, 9},
	DomainComponent:    []int{0, 9, 2342, 19200300, 100, 1, 25},
	UniqueIdentifier:   []int{0, 9, 2342, 19200300, 100, 1, 1},
}

// Copied from pkix.attributeTypeNames and inverted. (Sadly it is private.)
// Source: https://cs.opensource.google/go/go/+/refs/tags/go1.18.2:src/crypto/x509/pkix/pkix.go;l=26
// Added RDNs identifier to support rfc4514 LDAP certificates, cf https://github.com/cert-manager/cert-manager/issues/5582
var attributeTypeNames = map[string][]int{
	"C":            OIDConstants.Country,
	"O":            OIDConstants.Organization,
	"OU":           OIDConstants.OrganizationalUnit,
	"CN":           OIDConstants.CommonName,
	"SERIALNUMBER": OIDConstants.SerialNumber,
	"L":            OIDConstants.Locality,
	"ST":           OIDConstants.Province,
	"STREET":       OIDConstants.StreetAddress,
	"DC":           OIDConstants.DomainComponent,
	"UID":          OIDConstants.UniqueIdentifier,
}

func UnmarshalSubjectStringToRDNSequence(subject string) (pkix.RDNSequence, error) {
	if strings.Contains(subject, "=#") {
		return nil, fmt.Errorf("unsupported distinguished name (DN) %q: notation does not support x509.subject identities containing \"=#\"", subject)
	}

	dns, err := ldap.ParseDN(subject)
	if err != nil {
		return nil, err
	}

	// Traverse the parsed RDNSequence in REVERSE order as RDNs in String format are expected to be written in reverse order.
	// Meaning, a string of "CN=Foo,OU=Bar,O=Baz" actually should have "O=Baz" as the first element in the RDNSequence.
	rdns := make(pkix.RDNSequence, 0, len(dns.RDNs))
	for i := range dns.RDNs {
		ldapRelativeDN := dns.RDNs[len(dns.RDNs)-i-1]

		atvs := make([]pkix.AttributeTypeAndValue, 0, len(ldapRelativeDN.Attributes))
		for _, ldapATV := range ldapRelativeDN.Attributes {
			atvs = append(atvs, pkix.AttributeTypeAndValue{
				Type:  attributeTypeNames[ldapATV.Type],
				Value: ldapATV.Value,
			})
		}
		rdns = append(rdns, atvs)
	}
	return rdns, nil
}

func IsASN1SubjectEmpty(asn1Subject []byte) bool {
	// emptyASN1Subject is the ASN.1 DER encoding of an empty Subject, which is
	// just an empty SEQUENCE.
	var emptyASN1Subject = []byte{0x30, 0}

	return bytes.Equal(asn1Subject, emptyASN1Subject)
}

func MarshalRDNSequenceToRawDERBytes(rdnSequence pkix.RDNSequence) ([]byte, error) {
	return asn1.Marshal(rdnSequence)
}

func UnmarshalRawDerBytesToRDNSequence(der []byte) (rdnSequence pkix.RDNSequence, err error) {
	var rest []byte

	if rest, err = asn1.Unmarshal(der, &rdnSequence); err != nil {
		return rdnSequence, err
	} else if len(rest) != 0 {
		return rdnSequence, errors.New("RDNSequence: trailing data after Subject")
	} else {
		return rdnSequence, nil
	}
}

func ExtractCommonNameFromRDNSequence(rdns pkix.RDNSequence) string {
	for _, rdn := range rdns {
		for _, atv := range rdn {
			if atv.Type.Equal(OIDConstants.CommonName) {
				if str, ok := atv.Value.(string); ok {
					return str
				}
			}
		}
	}

	return ""
}

// DEPRECATED: this function will be removed in a future release.
func ParseSubjectStringToRawDERBytes(subject string) ([]byte, error) {
	rdnSequence, err := UnmarshalSubjectStringToRDNSequence(subject)
	if err != nil {
		return nil, err
	}

	return MarshalRDNSequenceToRawDERBytes(rdnSequence)
}
