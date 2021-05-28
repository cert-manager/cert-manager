/*
Copyright 2021 The cert-manager Authors.

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

package util

import (
	"reflect"
	"testing"
)

func TestIssuerRefFromSignerName(t *testing.T) {
	tests := map[string]struct {
		inpName            string
		expSignerIssuerRef SignerIssuerRef
		expOK              bool
	}{
		"an empty name should return false": {
			inpName:            "",
			expSignerIssuerRef: SignerIssuerRef{},
			expOK:              false,
		},
		"a reference without a name should return false": {
			inpName:            "foo.bar",
			expSignerIssuerRef: SignerIssuerRef{},
			expOK:              false,
		},
		"a reference with a '/' but no name should return false": {
			inpName:            "foo.bar/",
			expSignerIssuerRef: SignerIssuerRef{},
			expOK:              false,
		},
		"a reference with no host should return false": {
			inpName:            "/foo.bar",
			expSignerIssuerRef: SignerIssuerRef{},
			expOK:              false,
		},
		"a reference with only one domain should return false": {
			inpName:            "abc/hello-world",
			expSignerIssuerRef: SignerIssuerRef{},
			expOK:              false,
		},
		"a reference with multiple dots in the path should return a name with multiple dots": {
			inpName: "foo.bar/hello.world.123",
			expSignerIssuerRef: SignerIssuerRef{
				Namespace: "hello",
				Name:      "world.123",
				Type:      "foo",
				Group:     "bar",
			},
			expOK: true,
		},
		"a reference with 2 domains and 2 names should return namespaced issuer": {
			inpName: "foo.bar/hello.world",
			expSignerIssuerRef: SignerIssuerRef{
				Namespace: "hello",
				Name:      "world",
				Type:      "foo",
				Group:     "bar",
			},
			expOK: true,
		},
		"a reference with 4 domains and 4 names should return namespaced issuer": {
			inpName: "foo.bar.abc.dbc/hello.world.123.456",
			expSignerIssuerRef: SignerIssuerRef{
				Namespace: "hello",
				Name:      "world.123.456",
				Type:      "foo",
				Group:     "bar.abc.dbc",
			},
			expOK: true,
		},
		"a reference with 2 domains and one name should return cluster issuer": {
			inpName: "foo.bar/hello-world",
			expSignerIssuerRef: SignerIssuerRef{
				Namespace: "",
				Name:      "hello-world",
				Type:      "foo",
				Group:     "bar",
			},
			expOK: true,
		},
		"a reference with 4 domains and 1 name should return cluster issuer": {
			inpName: "foo.bar.abc.dbc/hello-world",
			expSignerIssuerRef: SignerIssuerRef{
				Namespace: "",
				Name:      "hello-world",
				Type:      "foo",
				Group:     "bar.abc.dbc",
			},
			expOK: true,
		},
		"a clusterissuers reference with 4 domains and multiple names should return no Namespace and multiple domain name": {
			inpName: "clusterissuers.bar.abc.dbc/hello.world.123.456",
			expSignerIssuerRef: SignerIssuerRef{
				Namespace: "",
				Name:      "hello.world.123.456",
				Type:      "clusterissuers",
				Group:     "bar.abc.dbc",
			},
			expOK: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ref, ok := SignerIssuerRefFromSignerName(test.inpName)
			if ok != test.expOK {
				t.Errorf("unexpected ok, exp=%t got=%t",
					test.expOK, ok)
			}

			if !reflect.DeepEqual(ref, test.expSignerIssuerRef) {
				t.Errorf("unexpected SignerIssuerRef, exp=%v got=%v",
					test.expSignerIssuerRef, ref)
			}
		})
	}
}
