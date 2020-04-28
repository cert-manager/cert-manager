/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package ctl

import (
	"strings"
	"testing"

	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/convert"
)

const (
	testdataResource1 = "./testdata/convert_resource1.yaml"
	testdataResource2 = "./testdata/convert_resource2.yaml"
	testdataResource3 = "./testdata/convert_resource3.yaml"

	targetv1alpha2 = "cert-manager.io/v1alpha2"
	targetv1alpha3 = "cert-manager.io/v1alpha3"
)

func TestCtlConvert(t *testing.T) {
	tests := map[string]struct {
		input, expOutput string
		targetVersion    string
		expErr           bool
	}{
		"a single cert-manager resource should convert to v1alpha2 with no target": {
			input:     testdataResource1,
			expOutput: resource1v1alpha2,
		},
		"a single cert-manager resource should convert to v1alpha2 with target v1alpha2": {
			input:         testdataResource1,
			targetVersion: targetv1alpha2,
			expOutput:     resource1v1alpha2,
		},
		"a single cert-manager resource should convert to v1alpha3 with target v1alpha3": {
			input:         testdataResource1,
			targetVersion: targetv1alpha3,
			expOutput:     resource1v1alpha3,
		},
		"a list of cert-manager resources should convert to v1alpha2 with no target": {
			input:     testdataResource2,
			expOutput: resource2v1alpha2,
		},
		"a list of cert-manager resources should convert to v1alpha2 with target v1alpha2": {
			input:     testdataResource2,
			expOutput: resource2v1alpha2,
		},
		"a list of cert-manager resources should convert to v1alpha3 with target v1alpha3": {
			input:         testdataResource2,
			targetVersion: targetv1alpha3,
			expOutput:     resource2v1alpha3,
		},
		"a list of a mix of cert-manager and non cert-manager resources should convert to v1alpha2 with no target": {
			input:         testdataResource2,
			targetVersion: targetv1alpha3,
			expOutput:     resource2v1alpha3,
		},
		"a list of a mix of cert-manager and non cert-manager resources should error with target v1alpha2": {
			input:         testdataResource3,
			targetVersion: targetv1alpha2,
			expErr:        true,
		},
		"a list of a mix of cert-manager and non cert-manager resources should error with target v1alpha3": {
			input:         testdataResource3,
			targetVersion: targetv1alpha3,
			expErr:        true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Run ctl convert command with input options
			streams, _, outBuf, _ := genericclioptions.NewTestIOStreams()

			opts := convert.NewOptions(streams)
			opts.OutputVersion = test.targetVersion
			opts.Filenames = []string{test.input}

			if err := opts.Complete(); err != nil {
				t.Fatal(err)
			}

			err := opts.Run()
			if test.expErr != (err != nil) {
				t.Errorf("got unexpected error, exp=%t got=%v",
					test.expErr, err)
			}

			if strings.TrimSpace(test.expOutput) != strings.TrimSpace(outBuf.String()) {
				t.Errorf("got unexpected output, exp=%s got=%s",
					strings.TrimSpace(test.expOutput), strings.TrimSpace(outBuf.String()))
			}
		})
	}
}

const (
	resource1v1alpha2 = `
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  creationTimestamp: null
  name: ca-issuer
  namespace: sandbox
spec:
  commonName: my-csi-app
  isCA: true
  issuerRef:
    group: cert-manager.io
    kind: Issuer
    name: selfsigned-issuer
  secretName: ca-key-pair
status: {}`
	resource1v1alpha3 = `
apiVersion: cert-manager.io/v1alpha3
kind: Certificate
metadata:
  creationTimestamp: null
  name: ca-issuer
  namespace: sandbox
spec:
  commonName: my-csi-app
  isCA: true
  issuerRef:
    group: cert-manager.io
    kind: Issuer
    name: selfsigned-issuer
  secretName: ca-key-pair
status: {}`

	resource2v1alpha2 = `
apiVersion: v1
items:
- apiVersion: cert-manager.io/v1alpha2
  kind: Certificate
  metadata:
    creationTimestamp: null
    name: ca-issuer
    namespace: sandbox
  spec:
    commonName: my-csi-app
    isCA: true
    issuerRef:
      group: cert-manager.io
      kind: Issuer
      name: selfsigned-issuer
    secretName: ca-key-pair
  status: {}
- apiVersion: cert-manager.io/v1alpha2
  kind: Issuer
  metadata:
    creationTimestamp: null
    name: ca-issuer
    namespace: sandbox
  spec:
    ca:
      secretName: ca-key-pair
  status: {}
- apiVersion: cert-manager.io/v1alpha2
  kind: Certificate
  metadata:
    creationTimestamp: null
    name: ca-issuer-2
    namespace: sandbox
  spec:
    commonName: my-csi-app
    isCA: true
    issuerRef:
      group: cert-manager.io
      kind: Issuer
      name: ca-issuer
    secretName: ca-key-pair
  status: {}
kind: List
metadata: {}`
	resource2v1alpha3 = `
apiVersion: v1
items:
- apiVersion: cert-manager.io/v1alpha3
  kind: Certificate
  metadata:
    creationTimestamp: null
    name: ca-issuer
    namespace: sandbox
  spec:
    commonName: my-csi-app
    isCA: true
    issuerRef:
      group: cert-manager.io
      kind: Issuer
      name: selfsigned-issuer
    secretName: ca-key-pair
  status: {}
- apiVersion: cert-manager.io/v1alpha3
  kind: Issuer
  metadata:
    creationTimestamp: null
    name: ca-issuer
    namespace: sandbox
  spec:
    ca:
      secretName: ca-key-pair
  status: {}
- apiVersion: cert-manager.io/v1alpha3
  kind: Certificate
  metadata:
    creationTimestamp: null
    name: ca-issuer-2
    namespace: sandbox
  spec:
    commonName: my-csi-app
    isCA: true
    issuerRef:
      group: cert-manager.io
      kind: Issuer
      name: ca-issuer
    secretName: ca-key-pair
  status: {}
kind: List
metadata: {}`

	resource3v1alpha2 = `
apiVersion: v1
items:
- apiVersion: v1
  kind: Namespace
  metadata:
    creationTimestamp: null
    name: sandbox
  spec: {}
  status: {}
- apiVersion: cert-manager.io/v1alpha2
  kind: Issuer
  metadata:
    creationTimestamp: null
    name: selfsigned-issuer
    namespace: sandbox
  spec:
    selfSigned: {}
  status: {}
kind: List
metadata: {}`
)
