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
	cmapiv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
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

	testWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var (
		cr1Name = "testcr-1"
		cr2Name = "testcr-2"
		cr3Name = "testcr-3"
		cr4Name = "testcr-4"
		cr5Name = "testcr-5"
		cr6Name = "testcr-6"
		ns1     = "testns-1"
		ns2     = "testns-2"

		testdataPath = testWorkingDirectory + "/testdata/"
	)

	tests := map[string]struct {
		inputFile      string
		inputArgs      []string
		inputNamespace string
		keyFilename    string
		certFilename   string
		fetchCert      bool
		timeout        time.Duration

		expValidateErr  bool
		expRunErr       bool
		expNamespace    string
		expName         string
		expKeyFilename  string
		expCertFilename string
	}{
		"v1alpha2 Certificate given": {
			inputFile:      testdataPath + "create_cr_cert_with_ns1.yaml",
			inputArgs:      []string{cr1Name},
			inputNamespace: ns1,
			keyFilename:    "",
			expValidateErr: false,
			expRunErr:      false,
			expNamespace:   ns1,
			expName:        cr1Name,
			expKeyFilename: cr1Name + ".key",
		},
		"v1alpha3 Certificate given": {
			inputFile:      testdataPath + "create_cr_v1alpha3_cert_with_ns1.yaml",
			inputArgs:      []string{cr2Name},
			inputNamespace: ns1,
			keyFilename:    "",
			expValidateErr: false,
			expRunErr:      false,
			expNamespace:   ns1,
			expName:        cr2Name,
			expKeyFilename: cr2Name + ".key",
		},
		"conflicting namespaces defined in flag and file": {
			inputFile:      testdataPath + "create_cr_cert_with_ns1.yaml",
			inputArgs:      []string{cr3Name},
			inputNamespace: ns2,
			keyFilename:    "",
			expValidateErr: false,
			expRunErr:      true,
			expNamespace:   "",
			expName:        "",
			expKeyFilename: "",
		},
		"file passed in defines resource other than certificate": {
			inputFile:      testdataPath + "create_cr_issuer.yaml",
			inputArgs:      []string{cr4Name},
			inputNamespace: ns1,
			keyFilename:    "",
			expValidateErr: false,
			expRunErr:      true,
			expNamespace:   "",
			expName:        "",
			expKeyFilename: "",
		},
		"path to file to store private key provided": {
			inputFile:      testdataPath + "create_cr_cert_with_ns1.yaml",
			inputArgs:      []string{cr5Name},
			inputNamespace: ns1,
			keyFilename:    "test.key",
			expValidateErr: false,
			expRunErr:      false,
			expNamespace:   ns1,
			expName:        cr5Name,
			expKeyFilename: "test.key",
		},
		"CR name not passed as arg": {
			inputFile:      testdataPath + "create_cr_cert_with_ns1.yaml",
			inputArgs:      []string{},
			inputNamespace: ns1,
			keyFilename:    "",
			expValidateErr: true,
			expRunErr:      false,
			expNamespace:   ns1,
			expKeyFilename: "",
		},
		"fetch flag set": {
			inputFile:       testdataPath + "create_cr_cert_with_ns1.yaml",
			inputArgs:       []string{cr6Name},
			inputNamespace:  ns1,
			keyFilename:     "",
			fetchCert:       true,
			timeout:         5 * time.Minute,
			expValidateErr:  false,
			expRunErr:       false,
			expNamespace:    ns1,
			expName:         cr6Name,
			expKeyFilename:  cr6Name + ".key",
			expCertFilename: cr6Name + ".crt",
		},
	}

	for name, test := range tests {
		// Run ctl create cr command with input options
		t.Run(name, func(t *testing.T) {
			streams, _, _, _ := genericclioptions.NewTestIOStreams()

			cleanUpFunc := setupPathForTest(t)
			defer cleanUpFunc()

			// Options to run create CR command
			opts := &certificaterequest.Options{
				CMClient:         cmCl,
				RESTConfig:       config,
				IOStreams:        streams,
				CmdNamespace:     test.inputNamespace,
				EnforceNamespace: test.inputNamespace != "",
				KeyFilename:      test.keyFilename,
				FetchCert:        test.fetchCert,
				Timeout:          test.timeout,
			}

			opts.InputFilename = test.inputFile

			// Validating args and flags
			err := opts.Validate(test.inputArgs)
			if err != nil {
				if !test.expValidateErr {
					t.Errorf("got unexpected error when validating args and flags: %v", err)
				}
				t.Logf("got an error, which was expected, details: %v", err)
				return
			} else {
				// got no error
				if test.expValidateErr {
					t.Errorf("expected but got no error validating args and flags")
				}
			}

			// Try to set Ready Condition if needed, otherwise the test just times out
			if test.fetchCert {
				go setCRReadyCondition(t, cmCl, test.inputArgs[0], test.inputNamespace)
			}
			// Create CR
			err = opts.Run(test.inputArgs)
			if err != nil {
				// TODO: Maybe it is desirable to make the test more fine grained, i.e. specify which error is expected,
				// to know where exactly things should fail and then check the correctness of the parts that shouldn't have failed
				if !test.expRunErr {
					t.Errorf("got unexpected error when trying to create CR: %v", err)
				} else {
					t.Logf("got an error, which was expected, details: %v", err)
				}
				return
			} else {
				// got no error
				if test.expRunErr {
					t.Errorf("expected but got no error when creating CR")
				}
			}

			// Finished creating CR, check if everything is expected
			crName := test.inputArgs[0]
			gotCr, err := cmCl.CertmanagerV1alpha2().CertificateRequests(test.inputNamespace).Get(ctx, crName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if gotCr.Name != test.expName {
				t.Errorf("CR created has unexpected Name, expected: %s, actual: %s", test.expName, gotCr.Name)
			}

			if gotCr.Namespace != test.expNamespace {
				t.Errorf("CR created in unexpected Namespace, expected: %s, actual: %s", test.expNamespace, gotCr.Namespace)
			}

			// Check the file where the private key is stored
			keyData, err := ioutil.ReadFile(test.expKeyFilename)
			if err != nil {
				t.Errorf("error when reading file storing private key: %v", err)
			}
			_, err = pki.DecodePrivateKeyBytes(keyData)
			if err != nil {
				t.Errorf("invalid private key: %v", err)
			}

			// Check the file where the certificate is stored if applicable
			if test.fetchCert {
				_, err := ioutil.ReadFile(test.expCertFilename)
				if err != nil {
					t.Errorf("error when reading file storing private key: %v", err)
				}
			}
		})
	}
}

func setupPathForTest(t *testing.T) func() {
	workingDirectoryBeforeTest, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// Create tmp directory and cd into it to store private key files
	tmpDir, err := ioutil.TempDir("", "tmp-ctl-test-*")
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Chdir(workingDirectoryBeforeTest); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatal(err)
		}
	}
}

// Retry to ensure CR has been created for up to a timeout and then
// set the Ready Condition of CR to true
func setCRReadyCondition(t *testing.T, cmCl versioned.Interface, crName, crNamespace string) {
	timeout := time.After(5 * time.Minute)
	tick := time.Tick(1 * time.Second)
	for {
		select {
		case <-timeout:
			t.Fatal("timeout waiting for CertificateRequest to be signed, retry later with fetch command")
		case <-tick:
			req, err := cmCl.CertmanagerV1alpha2().CertificateRequests(crNamespace).Get(context.TODO(), crName, metav1.GetOptions{})
			if err != nil {
				continue
			}
			// CR has been created, try update status
			readyCond := cmapiv1alpha2.CertificateRequestCondition{Type: cmapiv1alpha2.CertificateRequestConditionReady, Status: cmmeta.ConditionTrue}
			req.Status.Conditions = []cmapiv1alpha2.CertificateRequestCondition{readyCond}
			_, err = cmCl.CertmanagerV1alpha2().CertificateRequests(crNamespace).UpdateStatus(context.TODO(), req, metav1.UpdateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			return
		}
	}
}
