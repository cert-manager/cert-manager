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
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

const (
	nameTypeOtherName = 0
	nameTypeEmail     = 1
	nameTypeDNS       = 2
	nameTypeURI       = 6
	nameTypeIP        = 7
)

var oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
var otherNameParam = fmt.Sprintf("tag:%d", nameTypeOtherName)

type OtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  StringValueLikeType `asn1:"tag:0"`
}

// StringValueLikeType type for asn1 encoding. This will hold
// our utf-8 encoded string.
type StringValueLikeType struct {
	A string `asn1:"utf8"`
}

func buildSANExtensionIncludingOtherNameSANsForCertificate(crt *v1.Certificate) (pkix.Extension, error) {
	rawVals := make([]asn1.RawValue, 0)

	for index, otherNameSAN := range crt.Spec.OtherNameSANs {
		oidRegex, err := regexp.Compile("(([[:digit:]]+|\\.)+)")
		if err != nil {
			return pkix.Extension{}, err
		}

		output := oidRegex.FindStringSubmatch(otherNameSAN.OID)
		if len(output) <= 1 {
			return pkix.Extension{}, fmt.Errorf("Invalid OID in otherName SAN supplied: index: %d, type %v", index, otherNameSAN)
		}

		// extract first match of first capture group
		OIDString := output[1]

		parsedOID := asn1.ObjectIdentifier{}
		// we know this is a "valid" OID so convert:
		for _, elem := range strings.Split(OIDString, ".") {
			oidElem, err := strconv.Atoi(elem)
			if err != nil {
				return pkix.Extension{}, fmt.Errorf("Unexpected error while parsing otherName OID SAN: index: %d, type %s, error: %s", index, otherNameSAN.OID, err.Error())
			}
			parsedOID = append(parsedOID, oidElem)
		}

		otherNameDER, err := asn1.MarshalWithParams(OtherName{
			TypeID: parsedOID,
			Value: StringValueLikeType{
				A: otherNameSAN.StringValue,
			},
		}, otherNameParam)

		if err != nil {
			return pkix.Extension{}, fmt.Errorf("Failed to marshal otherName")
		}

		rawVals = append(rawVals, asn1.RawValue{
			FullBytes: otherNameDER})

	}

	// add all 'classic' generalNames

	iPAddresses := IPAddressesForCertificate(crt)

	dnsNames, err := DNSNamesForCertificate(crt)
	if err != nil {
		return pkix.Extension{}, err
	}

	uriNames, err := URIsForCertificate(crt)
	if err != nil {
		return pkix.Extension{}, err
	}

	stdRawVals, err := marshalSANs(dnsNames, crt.Spec.EmailAddresses, iPAddresses, uriNames)
	if err != nil {
		return pkix.Extension{}, err
	}

	rawVals = append(rawVals, stdRawVals...)

	SANDerBytes, err := asn1.Marshal(rawVals)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: false,
		Value:    SANDerBytes,
	}, nil
}

// adapted from https://cs.opensource.google/go/go/+/refs/tags/go1.21.2:src/crypto/x509/x509.go;l=1166-1167
// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) (rawVals []asn1.RawValue, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		if err := isIA5String(name); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		if err := isIA5String(email); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		uriStr := uri.String()
		if err := isIA5String(uriStr); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uriStr)})
	}
	return rawValues, nil
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
