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
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/create/certificaterequest"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/jetstack/cert-manager/test/integration/framework"
)

func TestCtlCreateCR(t *testing.T) {
	config, stopFn := framework.RunControlPlane(t)
	defer stopFn()

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*20)
	defer cancel()

	// Build clients
	_, _, cmCl, _ := framework.NewClients(t, config)

	// Create tmp directory and cd into it to store private key files
	dir, err := ioutil.TempDir(".", "tmp")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer cleanUpTmpDir(dir)

	var (
		cr1Name = "testcr-1"
		cr2Name = "testcr-2"
		cr3Name = "testcr-3"
		cr4Name = "testcr-4"
		cr5Name = "testcr-5"
		ns1     = "testns-1"
		ns2     = "testns-2"

		testdataPath = "../testdata/"
	)

	tests := map[string]struct {
		inputFile      string
		inputArgs      []string
		inputNamespace string
		keyFilename    string

		expErr         bool
		expNamespace   string
		expName        string
		expNamePrefix  string
		expKeyFilename string
	}{
		"v1alpha2 Certificate given": {
			inputFile:      testdataPath + "create_cr_cert_with_ns1.yaml",
			inputArgs:      []string{cr1Name},
			inputNamespace: ns1,
			keyFilename:    "",
			expErr:         false,
			expNamespace:   ns1,
			expName:        cr1Name,
			expKeyFilename: cr1Name + ".key",
		},
		"v1alpha3 Certificate given": {
			inputFile:      testdataPath + "create_cr_v1alpha3_cert_with_ns1.yaml",
			inputArgs:      []string{cr2Name},
			inputNamespace: ns1,
			keyFilename:    "",
			expErr:         false,
			expNamespace:   ns1,
			expName:        cr2Name,
			expKeyFilename: cr2Name + ".key",
		},
		"conflicting namespaces defined in flag and file": {
			inputFile:      testdataPath + "create_cr_cert_with_ns1.yaml",
			inputArgs:      []string{cr3Name},
			inputNamespace: ns2,
			keyFilename:    "",
			expErr:         true,
			expNamespace:   "",
			expName:        "",
			expKeyFilename: "",
		},
		"file passed in defines resource other than certificate": {
			inputFile:      testdataPath + "create_cr_issuer.yaml",
			inputArgs:      []string{cr4Name},
			inputNamespace: ns1,
			keyFilename:    "",
			expErr:         true,
			expNamespace:   "",
			expName:        "",
			expKeyFilename: "",
		},
		"path to file to store private key provided": {
			inputFile:      testdataPath + "create_cr_cert_with_ns1.yaml",
			inputArgs:      []string{cr5Name},
			inputNamespace: ns1,
			keyFilename:    "test.key",
			expErr:         false,
			expNamespace:   ns1,
			expName:        cr5Name,
			expKeyFilename: "test.key",
		},
		"CR name not passed as arg": {
			inputFile:      testdataPath + "create_cr_cert_with_ns1.yaml",
			inputArgs:      []string{},
			inputNamespace: ns1,
			keyFilename:    "",
			expErr:         false,
			expNamespace:   ns1,
			// Can't specify expected name as it will be generated randomly
			expNamePrefix:  "testcert-1-",
			expKeyFilename: "",
		},
	}

	for name, test := range tests {
		// Run ctl create cr command with input options
		t.Run(name, func(t *testing.T) {
			streams, _, _, _ := genericclioptions.NewTestIOStreams()

			// Options to run create CR command
			opts := &certificaterequest.Options{
				CMClient:         cmCl,
				RESTConfig:       config,
				IOStreams:        streams,
				CmdNamespace:     test.inputNamespace,
				EnforceNamespace: test.inputNamespace != "",
				KeyFilename:      test.keyFilename,
			}

			opts.InputFilename = test.inputFile

			err := opts.Run(test.inputArgs)

			if err != nil {
				if !test.expErr {
					t.Errorf("got unexpected error when trying to create CR: %v", err)
				}
				t.Logf("got an error, which was expected, details: %v", err)
				return
			} else {
				// got no error
				if test.expErr {
					t.Errorf("expected but got no error when creating CR")
				}
			}

			// Finished creating CR, check if everything is expected
			var gotCr *v1alpha2.CertificateRequest = nil

			if len(test.inputArgs) > 0 {
				// If CR name provided as arg, we can check if it is as expected
				crName := test.inputArgs[0]
				gotCr, err = cmCl.CertmanagerV1alpha2().CertificateRequests(test.inputNamespace).Get(ctx, crName, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}

				if gotCr.Name != test.expName {
					t.Errorf("CR created has unexpected Name, expected: %s, actual: %s", test.expName, gotCr.Name)
				}
			} else {
				// No arguments passed in, so the name of the CR will be generated from GenerateName, can't check exactly
				// Check for a CR with a name that has the name of the Certificate resource the CR is based on as prefix
				crList, err := cmCl.CertmanagerV1alpha2().CertificateRequests(test.inputNamespace).List(ctx, metav1.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}

				for _, crItem := range crList.Items {
					prefixLength := len(test.expNamePrefix)
					if len(crItem.Name) > prefixLength && crItem.Name[:prefixLength] == test.expNamePrefix {
						gotCr = &crItem
						break
					}
				}
				if gotCr == nil {
					t.Fatalf("no CR found with the expected prefix %q", test.expNamePrefix)
				}
			}

			if gotCr.Namespace != test.expNamespace {
				t.Errorf("CR created in unexpected Namespace, expected: %s, actual: %s", test.expNamespace, gotCr.Namespace)
			}

			// Check the file where the private key is stored
			expKeyFilename := test.expKeyFilename
			if test.keyFilename == "" && len(test.inputArgs) == 0 {
				expKeyFilename = gotCr.Name + ".key"
			}
			keyData, err := ioutil.ReadFile(expKeyFilename)
			if err != nil {
				t.Errorf("error when reading file storing private key: %v", err)
			}
			_, err = pki.DecodePrivateKeyBytes(keyData)
			if err != nil {
				t.Errorf("invalid private key: %v", err)
			}
		})
	}

	// Clean up tmp folder with private key files
	if err := os.Chdir(".."); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll("tmp"); err != nil {
		t.Fatal(err)
	}
}

func cleanUpTmpDir(dir string) error {
	if err := os.Chdir(".."); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return nil
}
