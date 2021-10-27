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

package featureset

import "strings"

// NewFeatureSet constructs a new feature set with the given features.
func NewFeatureSet(feats ...Feature) FeatureSet {
	fs := make(FeatureSet)
	for _, f := range feats {
		fs.Add(f)
	}
	return fs
}

// FeatureSet represents a set of features.
// This type does not indicate whether or not features are enabled, rather it
// just defines a grouping of features (i.e. a 'set').
type FeatureSet map[Feature]struct{}

// Add adds features to the set
func (fs FeatureSet) Add(f ...Feature) FeatureSet {
	for _, feat := range f {
		fs[feat] = struct{}{}
	}
	return fs
}

// Delete removes a feature from the set
func (fs FeatureSet) Delete(f Feature) {
	delete(fs, f)
}

// Contains returns true if the FeatureSet contains the given feature
func (fs FeatureSet) Contains(f Feature) bool {
	_, ok := fs[f]
	return ok
}

// Copy returns a new copy of an existing Feature Set.
// It is not safe to be called by multiple goroutines.
func (fs FeatureSet) Copy() FeatureSet {
	new := make(FeatureSet)
	for k, v := range fs {
		new[k] = v
	}
	return new
}

// List returns a slice of all features in the set.
func (fs FeatureSet) List() []Feature {
	var ret []Feature
	for k := range fs {
		ret = append(ret, k)
	}
	return ret
}

// String returns this FeatureSet as a comma separated string
func (fs FeatureSet) String() string {
	featsSlice := make([]string, len(fs))

	i := 0
	for f := range fs {
		featsSlice[i] = string(f)
		i++
	}

	return strings.Join(featsSlice, ", ")
}

type Feature string

// String returns the Feature name as a string
func (f Feature) String() string {
	return string(f)
}

const (
	// IPAddressFeature denotes tests that set the IPAddresses field.
	// Some issuer's are never going to allow issuing certificates with IP SANs
	// set as they are considered bad-practice.
	IPAddressFeature Feature = "IPAddresses"

	// DurationFeature denotes tests that set the 'duration' field to some
	// custom value.
	// Some issuers enforce a particular certificate duration, meaning they
	// will never pass tests that validate the duration is as expected.
	DurationFeature Feature = "Duration"

	// WildcardsFeature denotes tests that request certificates for wildcard
	// domains. Some issuer's disable wildcard certificate issuance, so this
	// feature allows runs of the suite to exclude those tests that utilise
	// wildcards.
	WildcardsFeature Feature = "Wildcards"

	// ECDSAFeature denotes whether the target issuer is able to sign
	// certificates with an elliptic curve private key.
	ECDSAFeature Feature = "ECDSA"

	// ReusePrivateKey denotes whether the target issuer is able to sign multiple
	// certificates for the same private key.
	ReusePrivateKeyFeature Feature = "ReusePrivateKey"

	// URISANs denotes whether to the target issuer is able to sign a certificate
	// that includes a URISANs. ACME providers do not support this.
	URISANsFeature Feature = "URISANs"

	// EmailSANs denotes whether to the target issuer is able to sign a certificate
	// that includes a EmailSANs.
	EmailSANsFeature Feature = "EmailSANs"

	// CommonName denotes whether the target issuer is able to sign certificates
	// with a distinct CommonName. This is useful for issuers such as ACME
	// providers that ignore, or otherwise have special requirements for the
	// CommonName such as needing to be present in the DNS Name list.
	CommonNameFeature = "CommonName"

	// KeyUsages denotes whether the target issuer is able to sign certificates
	// with arbitrary key usages.
	KeyUsagesFeature = "KeyUsages"

	// OnlySAN denotes whether the target issuer is able to sign certificates
	// with only SANs set
	OnlySAN = "OnlySAN"

	// SaveCAToSecret denotes whether the target issuer returns a CA
	// certificate which can be stored in the ca.crt field of the Secret.
	SaveCAToSecret = "SaveCAToSecret"

	// SaveRootCAToSecret denotes whether the CA certificate is expected to
	// represent a root CA (sub-feature of SaveCAToSecret)
	SaveRootCAToSecret = "SaveRootCAToSecret"

	// Ed25519FeatureSet denotes whether the target issuer is able to sign
	// certificates with an Ed25519 private key.
	Ed25519FeatureSet Feature = "Ed25519"

	// IssueCAFeature denotes whether the target issuer is able to issue CA
	// certificates (i.e., certificates for which the CA basicConstraint is true)
	IssueCAFeature Feature = "IssueCA"

	// LongDomainFeatureSet denotes whether the target issuer is able to sign
	// a certificate that defines a domain containing a label of 63 characters.
	LongDomainFeatureSet Feature = "LongDomain"
)
