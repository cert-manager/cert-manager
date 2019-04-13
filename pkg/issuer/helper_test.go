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

package issuer

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller/test"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestGetGenericIssuer(t *testing.T) {
	var nilIssuer *v1alpha1.Issuer
	var nilClusterIssuer *v1alpha1.ClusterIssuer
	type testT struct {
		Name                   string
		Kind                   string
		Namespace              string
		CMObjects              []runtime.Object
		NilClusterIssuerLister bool
		Err                    bool
		Expected               v1alpha1.GenericIssuer
	}
	tests := []testT{
		{
			Name:      "name-of-issuer",
			Kind:      "Issuer",
			Namespace: gen.DefaultTestNamespace,
			CMObjects: []runtime.Object{gen.Issuer("name-of-issuer")},
			Expected:  gen.Issuer("name-of-issuer"),
		},
		{
			Name:      "name-of-clusterissuer",
			Kind:      "ClusterIssuer",
			CMObjects: []runtime.Object{gen.ClusterIssuer("name-of-clusterissuer")},
			Expected:  gen.ClusterIssuer("name-of-clusterissuer"),
		},
		{
			Name:     "name",
			Kind:     "Issuer",
			Err:      true,
			Expected: nilIssuer,
		},
		{
			Name:     "name",
			Kind:     "ClusterIssuer",
			Err:      true,
			Expected: nilClusterIssuer,
		},
		{
			Name:     "name",
			Err:      true,
			Expected: nilIssuer,
		},
		{
			Name:                   "name",
			Kind:                   "ClusterIssuer",
			NilClusterIssuerLister: true,
			Err:                    true,
		},
	}

	for _, row := range tests {
		t.Run(row.Name, func(t *testing.T) {
			b := test.Builder{
				CertManagerObjects: row.CMObjects,
			}
			b.Start()
			c := &helperImpl{
				issuerLister:        b.FakeCMInformerFactory().Certmanager().V1alpha1().Issuers().Lister(),
				clusterIssuerLister: b.FakeCMInformerFactory().Certmanager().V1alpha1().ClusterIssuers().Lister(),
			}
			b.Sync()
			defer b.Stop()

			if row.NilClusterIssuerLister {
				c.clusterIssuerLister = nil
			}

			stopCh := make(chan struct{})
			defer close(stopCh)

			actual, err := c.GetGenericIssuer(v1alpha1.ObjectReference{Name: row.Name, Kind: row.Kind}, row.Namespace)
			if err != nil && !row.Err {
				t.Errorf("Expected no error, but got: %s", err)
			}
			if !reflect.DeepEqual(actual, row.Expected) {
				t.Errorf("Expected %#v but got %#v", row.Expected, actual)
			}
		})
	}
}
