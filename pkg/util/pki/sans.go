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
	// Value must already carry the explicit [0] wrapper, holding exactly one
	// well-formed element. The struct tag does not add it: encoding/asn1 honors
	// `tag:0,explicit` when reading a RawValue but writes a RawValue out
	// verbatim, so MarshalSANs emits whatever it is given here.
	Value asn1.RawValue `asn1:"tag:0,explicit"`
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
		// GeneralNames are always context-specific tagged (RFC 5280, 4.2.1.6).
		// crypto/x509 only matches context-specific tags; without this check the
		// switch below keys off the bare tag number, so an element encoded with a
		// different class (e.g. a UNIVERSAL tag 2) is misread as a dNSName.
		if v.Class != asn1.ClassContextSpecific {
			return asn1.StructuralError{Msg: "SAN GeneralName has invalid class"}
		}

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
			// directoryName is [4] Name, and Name is a CHOICE, so RFC 5280
			// section 4.2.1.6 (per X.680) requires the tag to be explicit.
			if _, err := asn1.UnmarshalWithParams(v.FullBytes, &rdn, fmt.Sprintf("explicit,tag:%d", nameTypeDirectoryName)); err != nil {
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

// checkSANsRoundTrip returns an error unless the SubjectAlternativeName
// contents in value parse back as the same GeneralNames they were built from.
//
// Several GeneralName choices are supplied by the caller as an asn1.RawValue,
// and encoding/asn1 writes a RawValue out verbatim - makeField returns early for
// rawValueType - so both the `tag:N` given to MarshalWithParams and the
// `asn1:"tag:0,explicit"` on OtherName.Value are honored when reading and
// ignored when writing. A value supplied without the tag its choice is defined
// with in RFC 5280 section 4.2.1.6 is therefore emitted as-is, and nothing
// reports a problem:
//
//   - an otherName missing its explicit [0] wrapper produces an extension that
//     UnmarshalSANs, in this same package, cannot read at all;
//   - an x400Address missing its [3] tag, whose own tag happens to be one of the
//     universal tags 0-8, is read back as a different GeneralName choice
//     entirely, because UnmarshalSANs dispatches on that tag.
//
// Checking the finished bytes against the parser keeps the two in agreement by
// construction, for every choice at once and for any choice added later, rather
// than one hand-rolled check per loop that can drift from the parser it mirrors
// - which is the class of bug being fixed here.
func checkSANsRoundTrip(value []byte, gns GeneralNames) error {
	const cause = "a GeneralName value supplied without the tag RFC 5280 section 4.2.1.6 defines it with will do this"

	parsed, err := UnmarshalSANs(value)
	if err != nil {
		return fmt.Errorf("x509: the SubjectAlternativeName contents cannot be parsed back; %s: %w", cause, err)
	}

	for _, choice := range []struct {
		name     string
		encoded  int
		readBack int
	}{
		{"otherName", len(gns.OtherNames), len(parsed.OtherNames)},
		{"rfc822Name", len(gns.RFC822Names), len(parsed.RFC822Names)},
		{"dNSName", len(gns.DNSNames), len(parsed.DNSNames)},
		{"x400Address", len(gns.X400Addresses), len(parsed.X400Addresses)},
		{"directoryName", len(gns.DirectoryNames), len(parsed.DirectoryNames)},
		{"ediPartyName", len(gns.EDIPartyNames), len(parsed.EDIPartyNames)},
		{"uniformResourceIdentifier", len(gns.UniformResourceIdentifiers), len(parsed.UniformResourceIdentifiers)},
		{"iPAddress", len(gns.IPAddresses), len(parsed.IPAddresses)},
		{"registeredID", len(gns.RegisteredIDs), len(parsed.RegisteredIDs)},
	} {
		if choice.encoded != choice.readBack {
			return fmt.Errorf("x509: encoded %d %s(s) but %d parsed back; %s",
				choice.encoded, choice.name, choice.readBack, cause)
		}
	}

	// value is [0] EXPLICIT ANY, so exactly one well-formed element belongs
	// inside the wrapper. encoding/asn1 does not descend into a RawValue under an
	// explicit tag, so the round-trip above is satisfied by a wrapper holding
	// arbitrary bytes - which matchOtherNames, reading this same field, then
	// fails on.
	for i, otherName := range parsed.OtherNames {
		var inner asn1.RawValue
		rest, err := asn1.Unmarshal(otherName.Value.Bytes, &inner)
		if err != nil {
			return fmt.Errorf("x509: otherName %d: the explicitly tagged value is not valid DER: %w", i, err)
		}
		if len(rest) != 0 {
			return fmt.Errorf("x509: otherName %d: trailing data after the explicitly tagged value", i)
		}
	}

	return nil
}

// adapted from https://cs.opensource.google/go/go/+/master:src/crypto/x509/x509.go;l=1059-1103;drc=e2d9574b14b3db044331da0c6fadeb62315c644a
// MarshalSANs marshals a list of addresses into the contents of an X.509
// SubjectAlternativeName extension.
func MarshalSANs(gns GeneralNames, hasSubject bool) (pkix.Extension, error) {
	var rawValues []asn1.RawValue
	// tag is ignored when val is an asn1.RawValue: encoding/asn1 writes a
	// RawValue out verbatim, so such a value has to carry its own tag already.
	// checkSANsRoundTrip, below, is what enforces that.
	addMarshalable := func(tag int, val any) error {
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
		// directoryName is [4] Name, and Name is a CHOICE, so RFC 5280
		// section 4.2.1.6 (per X.680) requires the tag to be explicit.
		fullBytes, err := asn1.MarshalWithParams(val, fmt.Sprintf("explicit,tag:%d", nameTypeDirectoryName))
		if err != nil {
			return pkix.Extension{}, err
		}
		rawValues = append(rawValues, asn1.RawValue{FullBytes: fullBytes})
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

	if err := checkSANsRoundTrip(byteValue, gns); err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: !hasSubject,
		Value:    byteValue,
	}, nil
}
