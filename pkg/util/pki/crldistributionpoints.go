package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Copied from https://github.com/golang/go/blob/go1.24.4/src/crypto/x509/x509.go#L1375-L1396
var (
	OIDExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
)

// Copied from https://github.com/golang/go/blob/go1.24.4/src/crypto/x509/x509.go#L1066-L1075
type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

// Adapted from https://github.com/golang/go/blob/go1.24.4/src/crypto/x509/x509.go#L1375-L1396
func MarshalCRLDistributionPoints(crlDistributionPoints []string) (pkix.Extension, error) {
	ext := pkix.Extension{Id: OIDExtensionCRLDistributionPoints, Critical: false}
	var crlDp []distributionPoint
	for _, name := range crlDistributionPoints {
		dp := distributionPoint{
			DistributionPoint: distributionPointName{
				FullName: []asn1.RawValue{
					{Tag: asn1.TagOID, Class: asn1.ClassContextSpecific, Bytes: []byte(name)},
				},
			},
		}
		crlDp = append(crlDp, dp)
	}

	extValue, err := asn1.Marshal(crlDp)
	ext.Value = extValue
	if err != nil {
		return ext, fmt.Errorf("failed to build CRLDistributionPoints: %w", err)
	}
	return ext, nil
}

// Adapted from https://github.com/golang/go/blob/go1.24.4/src/crypto/x509/parser.go#L705-L748
func UnmarshalCRLDistributionPoints(value []byte) ([]string, error) {
	// RFC 5280, 4.2.1.13

	// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
	//
	// DistributionPoint ::= SEQUENCE {
	//     distributionPoint       [0]     DistributionPointName OPTIONAL,
	//     reasons                 [1]     ReasonFlags OPTIONAL,
	//     cRLIssuer               [2]     GeneralNames OPTIONAL }
	//
	// DistributionPointName ::= CHOICE {
	//     fullName                [0]     GeneralNames,
	//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
	val := cryptobyte.String(value)
	var crlDistributionPoints []string

	if !val.ReadASN1(&val, cryptobyte_asn1.SEQUENCE) {
		return crlDistributionPoints, errors.New("x509: invalid CRL distribution points")
	}
	for !val.Empty() {
		var dpDER cryptobyte.String
		if !val.ReadASN1(&dpDER, cryptobyte_asn1.SEQUENCE) {
			return crlDistributionPoints, errors.New("x509: invalid CRL distribution point")
		}
		var dpNameDER cryptobyte.String
		var dpNamePresent bool
		if !dpDER.ReadOptionalASN1(&dpNameDER, &dpNamePresent, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			return crlDistributionPoints, errors.New("x509: invalid CRL distribution point")
		}
		if !dpNamePresent {
			continue
		}
		if !dpNameDER.ReadASN1(&dpNameDER, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			return crlDistributionPoints, errors.New("x509: invalid CRL distribution point")
		}
		for !dpNameDER.Empty() {
			if !dpNameDER.PeekASN1Tag(cryptobyte_asn1.Tag(6).ContextSpecific()) {
				break
			}
			var uri cryptobyte.String
			if !dpNameDER.ReadASN1(&uri, cryptobyte_asn1.Tag(6).ContextSpecific()) {
				return crlDistributionPoints, errors.New("x509: invalid CRL distribution point")
			}
			crlDistributionPoints = append(crlDistributionPoints, string(uri))
		}
	}
	return crlDistributionPoints, nil
}
