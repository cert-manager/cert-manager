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
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// Copied from x509.go
var (
	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
)

// Based on RFC 5280, section 4.2.1.6
// see https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
/*
	OtherName ::= SEQUENCE {
		type-id    OBJECT IDENTIFIER,
		value      [0] EXPLICIT ANY DEFINED BY type-id }
*/
type OtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"tag:0,explicit"`
}

// Based on RFC 5280, section 4.2.1.6
// see https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
/*
	EDIPartyName ::= SEQUENCE {
		nameAssigner            [0]     DirectoryString OPTIONAL,
		partyName               [1]     DirectoryString }
*/
type EDIPartyName struct {
	NameAssigner string `asn1:"tag:0,optional"`
	PartyName    string `asn1:"tag:1"`
}

// Based on RFC 5280, section 4.2.1.6
// see https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
/*
	GeneralName ::= CHOICE {
		otherName                       [0]     OtherName,
		rfc822Name                      [1]     IA5String,
		dnsName                         [2]     IA5String,
		x400Address                     [3]     ORAddress,
		directoryName                   [4]     Name,
		ediPartyName                    [5]     EDIPartyName,
		uniformResourceIdentifier       [6]     IA5String,
		ipAddress                       [7]     OCTET STRING,
		registeredID                    [8]     OBJECT IDENTIFIER }
*/
const (
	nameTypeOtherName                 = 0
	nameTypeRFC822Name                = 1
	nameTypeDNSName                   = 2
	nameTypeX400Address               = 3
	nameTypeDirectoryName             = 4
	nameTypeEDIPartyName              = 5
	nameTypeUniformResourceIdentifier = 6
	nameTypeIPAddress                 = 7
	nameTypeRegisteredID              = 8
)

type GeneralNames struct {
	OtherNames                 []OtherName
	RFC822Names                []string
	DNSNames                   []string
	X400Addresses              []asn1.RawValue
	DirectoryNames             []pkix.RDNSequence
	EDIPartyNames              []EDIPartyName
	UniformResourceIdentifiers []string
	IPAddresses                []net.IP
	RegisteredIDs              []asn1.ObjectIdentifier
}

func (gns GeneralNames) Empty() bool {
	return len(gns.OtherNames) == 0 &&
		len(gns.RFC822Names) == 0 &&
		len(gns.DNSNames) == 0 &&
		len(gns.X400Addresses) == 0 &&
		len(gns.DirectoryNames) == 0 &&
		len(gns.EDIPartyNames) == 0 &&
		len(gns.UniformResourceIdentifiers) == 0 &&
		len(gns.IPAddresses) == 0 &&
		len(gns.RegisteredIDs) == 0
}

// adapted from https://cs.opensource.google/go/go/+/master:src/crypto/x509/parser.go;l=373-416;drc=16d3040a84be821d801b75bd1a3d8ab4cc89ee36
func UnmarshalSANs(value []byte) (GeneralNames, error) {
	var gns GeneralNames
	err := forEachSAN(value, func(v asn1.RawValue) error {
		switch v.Tag {
		case nameTypeOtherName:
			var otherName OtherName
			if _, err := asn1.UnmarshalWithParams(v.FullBytes, &otherName, fmt.Sprintf("tag:%d", nameTypeOtherName)); err != nil {
				return err
			}
			gns.OtherNames = append(gns.OtherNames, otherName)
		case nameTypeRFC822Name:
			email := string(v.Bytes)
			if err := isIA5String(email); err != nil {
				return errors.New("x509: SAN rfc822Name is malformed")
			}
			gns.RFC822Names = append(gns.RFC822Names, email)
		case nameTypeDNSName:
			name := string(v.Bytes)
			if err := isIA5String(name); err != nil {
				return errors.New("x509: SAN dNSName is malformed")
			}
			gns.DNSNames = append(gns.DNSNames, name)
		case nameTypeX400Address:
			gns.X400Addresses = append(gns.X400Addresses, v)
		case nameTypeDirectoryName:
			var rdn pkix.RDNSequence
			if _, err := asn1.UnmarshalWithParams(v.FullBytes, &rdn, fmt.Sprintf("tag:%d", nameTypeDirectoryName)); err != nil {
				return err
			}
			gns.DirectoryNames = append(gns.DirectoryNames, rdn)
		case nameTypeEDIPartyName:
			var edipn EDIPartyName
			if _, err := asn1.UnmarshalWithParams(v.FullBytes, &edipn, fmt.Sprintf("tag:%d", nameTypeEDIPartyName)); err != nil {
				return err
			}
			gns.EDIPartyNames = append(gns.EDIPartyNames, edipn)
		case nameTypeUniformResourceIdentifier:
			uriStr := string(v.Bytes)
			if err := isIA5String(uriStr); err != nil {
				return errors.New("x509: SAN uniformResourceIdentifier is malformed")
			}
			gns.UniformResourceIdentifiers = append(gns.UniformResourceIdentifiers, uriStr)
		case nameTypeIPAddress:
			switch len(v.Bytes) {
			case net.IPv4len, net.IPv6len:
				gns.IPAddresses = append(gns.IPAddresses, v.Bytes)
			default:
				return errors.New("x509: cannot parse IP address of length " + strconv.Itoa(len(v.Bytes)))
			}
		case nameTypeRegisteredID:
			var oid asn1.ObjectIdentifier
			if _, err := asn1.UnmarshalWithParams(v.FullBytes, &oid, fmt.Sprintf("tag:%d", nameTypeRegisteredID)); err != nil {
				return err
			}
			gns.RegisteredIDs = append(gns.RegisteredIDs, oid)
		default:
			return asn1.StructuralError{Msg: "bad SAN choice"}
		}

		return nil
	})

	return gns, err
}

func forEachSAN(extension []byte, callback func(v asn1.RawValue) error) error {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return fmt.Errorf("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != asn1.TagSequence || seq.Class != asn1.ClassUniversal {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v); err != nil {
			return err
		}
	}

	return nil
}

// adapted from https://cs.opensource.google/go/go/+/master:src/crypto/x509/x509.go;l=1059-1103;drc=e2d9574b14b3db044331da0c6fadeb62315c644a
// MarshalSANs marshals a list of addresses into the contents of an X.509
// SubjectAlternativeName extension.
func MarshalSANs(gns GeneralNames, hasSubject bool) (pkix.Extension, error) {
	var rawValues []asn1.RawValue
	addMarshalable := func(tag int, val interface{}) error {
		fullBytes, err := asn1.MarshalWithParams(val, fmt.Sprint("tag:", tag))
		if err != nil {
			return err
		}
		rawValues = append(rawValues, asn1.RawValue{FullBytes: fullBytes})
		return nil
	}
	addIA5String := func(tag int, val string) error {
		if err := isIA5String(val); err != nil {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", val)
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: tag, Class: asn1.ClassContextSpecific, Bytes: []byte(val)})
		return nil
	}

	// Maintain the order of the SANs as produced by the Go x509 library.
	for _, val := range gns.DNSNames {
		if err := addIA5String(nameTypeDNSName, val); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, val := range gns.RFC822Names {
		if err := addIA5String(nameTypeRFC822Name, val); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, rawIP := range gns.IPAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIPAddress, Class: asn1.ClassContextSpecific, Bytes: ip})
	}
	for _, val := range gns.UniformResourceIdentifiers {
		if err := addIA5String(nameTypeUniformResourceIdentifier, val); err != nil {
			return pkix.Extension{}, err
		}
	}

	// Add support for the remaining SAN types.
	for _, val := range gns.OtherNames {
		if err := addMarshalable(nameTypeOtherName, val); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, val := range gns.X400Addresses {
		if err := addMarshalable(nameTypeX400Address, val); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, val := range gns.DirectoryNames {
		if err := addMarshalable(nameTypeDirectoryName, val); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, val := range gns.EDIPartyNames {
		if err := addMarshalable(nameTypeEDIPartyName, val); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, val := range gns.RegisteredIDs {
		if err := addMarshalable(nameTypeRegisteredID, val); err != nil {
			return pkix.Extension{}, err
		}
	}

	byteValue, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: !hasSubject,
		Value:    byteValue,
	}, nil
}
