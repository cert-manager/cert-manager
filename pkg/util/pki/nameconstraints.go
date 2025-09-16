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
	"errors"
	"fmt"
	"net"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Copied from x509.go
var (
	OIDExtensionNameConstraints = []int{2, 5, 29, 30}
)

// NameConstraints represents the NameConstraints extension.
type NameConstraints struct {
	PermittedDNSDomains     []string
	ExcludedDNSDomains      []string
	PermittedIPRanges       []*net.IPNet
	ExcludedIPRanges        []*net.IPNet
	PermittedEmailAddresses []string
	ExcludedEmailAddresses  []string
	PermittedURIDomains     []string
	ExcludedURIDomains      []string
}

func (nc NameConstraints) IsEmpty() bool {
	return len(nc.PermittedDNSDomains) == 0 &&
		len(nc.PermittedIPRanges) == 0 &&
		len(nc.PermittedEmailAddresses) == 0 &&
		len(nc.PermittedURIDomains) == 0 &&
		len(nc.ExcludedDNSDomains) == 0 &&
		len(nc.ExcludedIPRanges) == 0 &&
		len(nc.ExcludedEmailAddresses) == 0 &&
		len(nc.ExcludedURIDomains) == 0
}

// Adapted from x509.go
func MarshalNameConstraints(nameConstraints *NameConstraints, critical bool) (pkix.Extension, error) {
	ipAndMask := func(ipNet *net.IPNet) []byte {
		maskedIP := ipNet.IP.Mask(ipNet.Mask)
		ipAndMask := make([]byte, 0, len(maskedIP)+len(ipNet.Mask))
		ipAndMask = append(ipAndMask, maskedIP...)
		ipAndMask = append(ipAndMask, ipNet.Mask...)
		return ipAndMask
	}

	serialiseConstraints := func(dns []string, ips []*net.IPNet, emails []string, uriDomains []string) (der []byte, err error) {
		var b cryptobyte.Builder

		for _, name := range dns {
			if err = isIA5String(name); err != nil {
				return nil, err
			}

			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(name))
				})
			})
		}

		for _, ipNet := range ips {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.Tag(7).ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddBytes(ipAndMask(ipNet))
				})
			})
		}

		for _, email := range emails {
			if err = isIA5String(email); err != nil {
				return nil, err
			}

			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(email))
				})
			})
		}

		for _, uriDomain := range uriDomains {
			if err = isIA5String(uriDomain); err != nil {
				return nil, err
			}

			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(uriDomain))
				})
			})
		}

		return b.Bytes()
	}

	var permitted []byte
	var err error
	permitted, err = serialiseConstraints(nameConstraints.PermittedDNSDomains, nameConstraints.PermittedIPRanges, nameConstraints.PermittedEmailAddresses, nameConstraints.PermittedURIDomains)
	if err != nil {
		return pkix.Extension{}, err
	}

	var excluded []byte
	excluded, err = serialiseConstraints(nameConstraints.ExcludedDNSDomains, nameConstraints.ExcludedIPRanges, nameConstraints.ExcludedEmailAddresses, nameConstraints.ExcludedURIDomains)
	if err != nil {
		return pkix.Extension{}, err
	}

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if len(permitted) > 0 {
			b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(permitted)
			})
		}

		if len(excluded) > 0 {
			b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(excluded)
			})
		}
	})

	bytes, err := b.Bytes()
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       OIDExtensionNameConstraints,
		Critical: critical,
		Value:    bytes,
	}, nil
}

func parseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	ipRanges := []*net.IPNet{}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		ipRanges = append(ipRanges, &net.IPNet{
			IP:   ipNet.IP,
			Mask: ipNet.Mask,
		})
	}
	return ipRanges, nil
}

// Adapted from crypto/x509/parser.go
func UnmarshalNameConstraints(value []byte) (*NameConstraints, error) {
	// RFC 5280, 4.2.1.10

	// NameConstraints ::= SEQUENCE {
	//      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
	//      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
	//
	// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
	//
	// GeneralSubtree ::= SEQUENCE {
	//      base                    GeneralName,
	//      minimum         [0]     BaseDistance DEFAULT 0,
	//      maximum         [1]     BaseDistance OPTIONAL }
	//
	// BaseDistance ::= INTEGER (0..MAX)

	outer := cryptobyte.String(value)
	var toplevel, permitted, excluded cryptobyte.String
	var havePermitted, haveExcluded bool
	if !outer.ReadASN1(&toplevel, cryptobyte_asn1.SEQUENCE) ||
		!outer.Empty() ||
		!toplevel.ReadOptionalASN1(&permitted, &havePermitted, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) ||
		!toplevel.ReadOptionalASN1(&excluded, &haveExcluded, cryptobyte_asn1.Tag(1).ContextSpecific().Constructed()) ||
		!toplevel.Empty() {
		return nil, errors.New("x509: invalid NameConstraints extension")
	}

	if !havePermitted && !haveExcluded || len(permitted) == 0 && len(excluded) == 0 {
		// From RFC 5280, Section 4.2.1.10:
		//   “either the permittedSubtrees field
		//   or the excludedSubtrees MUST be
		//   present”
		return nil, errors.New("x509: empty name constraints extension")
	}

	getValues := func(subtrees cryptobyte.String) (dnsNames []string, ips []*net.IPNet, emails, uriDomains []string, err error) {
		for !subtrees.Empty() {
			var seq, value cryptobyte.String
			var tag cryptobyte_asn1.Tag
			if !subtrees.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) ||
				!seq.ReadAnyASN1(&value, &tag) {
				return nil, nil, nil, nil, fmt.Errorf("x509: invalid NameConstraints extension")
			}

			var (
				dnsTag   = cryptobyte_asn1.Tag(2).ContextSpecific()
				emailTag = cryptobyte_asn1.Tag(1).ContextSpecific()
				ipTag    = cryptobyte_asn1.Tag(7).ContextSpecific()
				uriTag   = cryptobyte_asn1.Tag(6).ContextSpecific()
			)

			switch tag {
			case dnsTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				dnsNames = append(dnsNames, domain)

			case ipTag:
				l := len(value)
				var ip, mask []byte

				switch l {
				case 2 * net.IPv4len:
					ip = value[:net.IPv4len]
					mask = value[net.IPv4len:]

				case 2 * net.IPv6len:
					ip = value[:net.IPv6len]
					mask = value[net.IPv6len:]

				default:
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained value of length %d", l)
				}

				if !isValidIPMask(mask) {
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained invalid mask %x", mask)
				}

				ips = append(ips, &net.IPNet{IP: net.IP(ip), Mask: net.IPMask(mask)})

			case emailTag:
				constraint := string(value)
				if err := isIA5String(constraint); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				emails = append(emails, constraint)

			case uriTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				uriDomains = append(uriDomains, domain)

			default:
				return nil, nil, nil, nil, fmt.Errorf("x509: unsupported NameConstraints tag: %v", tag)
			}
		}

		return dnsNames, ips, emails, uriDomains, nil
	}

	out := &NameConstraints{}

	var err error
	if out.PermittedDNSDomains, out.PermittedIPRanges, out.PermittedEmailAddresses, out.PermittedURIDomains, err = getValues(permitted); err != nil {
		return nil, err
	}
	if out.ExcludedDNSDomains, out.ExcludedIPRanges, out.ExcludedEmailAddresses, out.ExcludedURIDomains, err = getValues(excluded); err != nil {
		return nil, err
	}

	return out, nil
}

// isValidIPMask reports whether mask consists of zero or more 1 bits, followed by zero bits.
func isValidIPMask(mask []byte) bool {
	seenZero := false

	for _, b := range mask {
		if seenZero {
			if b != 0 {
				return false
			}

			continue
		}

		switch b {
		case 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe:
			seenZero = true
		case 0xff:
		default:
			return false
		}
	}

	return true
}
