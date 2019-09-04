/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package certificates

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

// Add adds a feature to the set
func (fs FeatureSet) Add(f Feature) {
	fs[f] = struct{}{}
}

// Delete removes a feature from the set
func (fs FeatureSet) Delete(f Feature) {
	_, ok := fs[f]
	if ok {
		delete(fs, f)
	}
}

// Contains returns true if the FeatureSet contains the given feature
func (fs FeatureSet) Contains(f Feature) bool {
	_, ok := fs[f]
	return ok
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

	// Wildcards denotes tests that request certificates for wildcard domains.
	// Some issuer's disable wildcard certificate issuance, so this feature
	// allows runs of the suite to exclude those tests that utilise wildcards.
	Wildcards Feature = "Wildcards"
)
