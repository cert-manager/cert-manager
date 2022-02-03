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

package certificaterequest

import (
	"context"
	"os"
	"testing"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
)

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		inputFile    string
		inputArgs    []string
		keyFilename  string
		certFilename string
		fetchCert    bool

		expErr    bool
		expErrMsg string
	}{
		"CR name not passed as arg throws error": {
			inputFile: "example.yaml",
			inputArgs: []string{},
			expErr:    true,
			expErrMsg: "the name of the CertificateRequest to be created has to be provided as argument",
		},
		"More than one arg throws error": {
			inputFile: "example.yaml",
			inputArgs: []string{"hello", "World"},
			expErr:    true,
			expErrMsg: "only one argument can be passed in: the name of the CertificateRequest",
		},
		"not specifying path to yaml manifest throws error": {
			inputFile: "",
			inputArgs: []string{"hello"},
			expErr:    true,
			expErrMsg: "the path to a YAML manifest of a Certificate resource cannot be empty, please specify by using --from-certificate-file flag",
		},
		"key filename and cert filename are optional flags": {
			inputFile:    "example.yaml",
			inputArgs:    []string{"hello"},
			keyFilename:  "",
			certFilename: "",
			expErr:       false,
		},
		"identical key filename and cert filename throws error": {
			inputFile:    "example.yaml",
			inputArgs:    []string{"hello"},
			keyFilename:  "same",
			certFilename: "same",
			expErr:       true,
			expErrMsg:    "the file to store private key cannot be the same as the file to store certificate",
		},
		"cannot specify cert filename without fetch-certificate flag": {
			inputFile:    "example.yaml",
			inputArgs:    []string{"hello"},
			certFilename: "cert.crt",
			fetchCert:    false,
			expErr:       true,
			expErrMsg:    "cannot specify file to store certificate if not waiting for and fetching certificate, please set --fetch-certificate flag",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			opts := &Options{
				InputFilename: test.inputFile,
				KeyFilename:   test.keyFilename,
				CertFileName:  test.certFilename,
				FetchCert:     test.fetchCert,
			}

			// Validating args and flags
			err := opts.Validate(test.inputArgs)
			if err != nil {
				if !test.expErr {
					t.Fatalf("got unexpected error when validating args and flags: %v", err)
				}
				if err.Error() != test.expErrMsg {
					t.Fatalf("got unexpected error when validating args and flags, expected: %v; actual: %v", test.expErrMsg, err)
				}
			} else if test.expErr {
				// got no error
				t.Errorf("expected but got no error validating args and flags")
			}
		})
	}
}

// Test Run tests the Run function's error behaviour up where it fails before interacting with
// other components, e.g. writing private key to file.
func TestRun(t *testing.T) {
	const (
		crName = "testcr-3"
		ns1    = "testns-1"
		ns2    = "testns-2"
	)

	tests := map[string]struct {
		inputFileContent string
		inputArgs        []string
		inputNamespace   string
		keyFilename      string
		certFilename     string
		fetchCert        bool

		expErr    bool
		expErrMsg string
	}{
		// Build clients
		"conflicting namespaces defined in flag and file": {
			inputFileContent: `---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: testcert-1
  namespace: testns-1
spec:
  isCA: true
  secretName: ca-key-pair
  commonName: my-csi-app
  issuerRef:
    name: selfsigned-issuer
    kind: Issuer
    group: cert-manager.io
`,
			inputArgs:      []string{crName},
			inputNamespace: ns2,
			keyFilename:    "",
			expErr:         true,
			expErrMsg:      "the namespace from the provided object \"testns-1\" does not match the namespace \"testns-2\". You must pass '--namespace=testns-1' to perform this operation.",
		},
		"file passed in defines resource other than certificate": {
			inputFileContent: `---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ca-issuer
  namespace: testns-1
spec:
  ca:
    secretName: ca-key-pair
`,
			inputArgs:      []string{crName},
			inputNamespace: ns1,
			keyFilename:    "",
			expErr:         true,
			expErrMsg:      "decoded object is not a v1 Certificate",
		},
		"empty manifest file throws error": {
			inputFileContent: ``,
			inputArgs:        []string{crName},
			inputNamespace:   ns1,
			keyFilename:      "",
			expErr:           true,
			expErrMsg:        "no objects found in manifest file \"testfile.yaml\". Expected one Certificate object",
		},
		"manifest file with multiple objects throws error": {
			inputFileContent: `---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ca-issuer
  namespace: testns-1
spec:
  ca:
    secretName: ca-key-pair
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: testcert-1
  namespace: testns-1
spec:
  isCA: true
  secretName: ca-key-pair
  commonName: my-csi-app
  issuerRef:
    name: selfsigned-issuer
    kind: Issuer
    group: cert-manager.io`,
			inputArgs:      []string{crName},
			inputNamespace: ns1,
			keyFilename:    "",
			expErr:         true,
			expErrMsg:      "multiple objects found in manifest file \"testfile.yaml\". Expected only one Certificate object",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile("testfile.yaml", []byte(test.inputFileContent), 0644); err != nil {
				t.Fatalf("error creating test file %#v", err)
			}
			defer os.Remove("testfile.yaml")

			// Options to run create CR command
			opts := &Options{
				InputFilename: "testfile.yaml",
				KeyFilename:   test.keyFilename,
				CertFileName:  test.certFilename,
				Factory: &factory.Factory{
					Namespace:        test.inputNamespace,
					EnforceNamespace: test.inputNamespace != "",
				},
			}

			// Validating args and flags
			err := opts.Validate(test.inputArgs)
			if err != nil {
				t.Fatal(err)
			}

			// Create CR
			err = opts.Run(context.TODO(), test.inputArgs)
			if err != nil {
				if !test.expErr {
					t.Fatalf("got unexpected error when trying to create CR: %v", err)
				}
				if err.Error() != test.expErrMsg {
					t.Fatalf("got unexpected error when trying to create CR, expected: %v; actual: %v", test.expErrMsg, err)
				}
			} else if test.expErr {
				// got no error
				t.Errorf("expected but got no error when creating CR")
			}
		})
	}
}
