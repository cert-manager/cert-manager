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
	"net"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// Copied from x509.go
var (
	OIDExtensionNameConstraints = []int{2, 5, 29, 30}
)

// NameConstraints represents the NameConstraints extension.
type NameConstraints struct {
	PermittedDNSDomainsCritical bool     `asn1:"optional,explicit,tag:0"`
	PermittedDNSDomains         []string  `asn1:"optional,explicit,tag:1"`
	ExcludedDNSDomains          []string  `asn1:"optional,explicit,tag:2"`
	PermittedIPRanges           []net.IPNet `asn1:"optional,explicit,tag:3"`
	ExcludedIPRanges            []net.IPNet `asn1:"optional,explicit,tag:4"`
	PermittedEmailAddresses     []string  `asn1:"optional,explicit,tag:5"`
	ExcludedEmailAddresses      []string  `asn1:"optional,explicit,tag:6"`
	PermittedURIDomains         []string  `asn1:"optional,explicit,tag:7"`
	ExcludedURIDomains          []string  `asn1:"optional,explicit,tag:8"`
}

// Adapted from x509.go
func MarshalNameConstraints(nameConstraints *v1.NameConstraints) (pkix.Extension, error) {
	ext := pkix.Extension{Id: OIDExtensionNameConstraints, Critical: true}
	var nameConstraintsForMarshalling NameConstraints
	if nameConstraints.Permitted != nil {
		permittedIPRanges, err := parseCIDRs(nameConstraints.Permitted.IPRanges)
		if err != nil {
			return pkix.Extension{}, err
		}
		nameConstraintsForMarshalling = NameConstraints{
			PermittedDNSDomainsCritical: nameConstraints.Permitted.Critical,
			PermittedDNSDomains: nameConstraints.Permitted.DNSDomains,
			PermittedIPRanges: permittedIPRanges,
			PermittedEmailAddresses: nameConstraints.Permitted.EmailAddresses,
			PermittedURIDomains: nameConstraints.Permitted.URIDomains,
		}
	}

	if nameConstraints.Excluded != nil {
		excludedIPRanges, err := parseCIDRs(nameConstraints.Excluded.IPRanges)
		if err != nil {
			return pkix.Extension{}, err
		}
		nameConstraintsForMarshalling.ExcludedDNSDomains = nameConstraints.Excluded.DNSDomains
		nameConstraintsForMarshalling.ExcludedIPRanges = excludedIPRanges
		nameConstraintsForMarshalling.ExcludedEmailAddresses = nameConstraints.Excluded.EmailAddresses
		nameConstraintsForMarshalling.ExcludedURIDomains = nameConstraints.Excluded.URIDomains
	}
	var err error
	ext.Value, err = asn1.Marshal(nameConstraintsForMarshalling)
	return ext, err
}

func parseCIDRs(cidrs []string) ([]net.IPNet, error) {
	ipRanges := []net.IPNet{}
	for _, cidr := range(cidrs) {
		_, ipNet, err := net.ParseCIDR(cidr)
		ipRanges = append(ipRanges, net.IPNet{
			IP:   ipNet.IP,
			Mask: ipNet.Mask,
		})
		if err != nil {
			return nil, err
		}
	}
	return ipRanges, nil
}

func UnmarshalNameConstraints(value []byte) (NameConstraints, error) {
	var constraints NameConstraints
	var rest []byte
	var err error
	if rest, err = asn1.Unmarshal(value, &constraints); err != nil {
		return constraints, err
	} else if len(rest) != 0 {
		return constraints, errors.New("x509: trailing data after X.509 NameConstraints")
	}

	return constraints, nil
}

// ConvertIPNeSliceToIPNetPointerSlice converts []net.IPNet to []*net.IPNet.
func ConvertIPNeSliceToIPNetPointerSlice(ipNetPointerSlice []net.IPNet) ([]*net.IPNet) {
	var ipNets []*net.IPNet
	for _, ipNet := range ipNetPointerSlice {
		ipNets = append(ipNets, &ipNet)
	}
	return ipNets
}