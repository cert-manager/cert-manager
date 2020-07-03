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
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/create/certificaterequest"
	cmapiv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
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
		exampleCertificate = []byte(`LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZUekNDQkRlZ0F3SUJBZ0lUQVBwOWhMUit2ODF2UTdpZSt6emxTMWY5MFRBTkJna3Foa2lHOXcwQkFRc0YKQURBaU1TQXdIZ1lEVlFRRERCZEdZV3RsSUV4RklFbHVkR1Z5YldWa2FXRjBaU0JZTVRBZUZ3MHlNREEyTXpBeApNelUyTkRoYUZ3MHlNREE1TWpneE16VTJORGhhTUNZeEpEQWlCZ05WQkFNVEcyaGhiM2hwWVc1bkxXZGpjQzVxClpYUnpkR0ZqYTJWeUxtNWxkRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFOTjIKTS9zZGtPazgvenJLbXNvMEE1SmxoUjRTQU9pTVhiWGZleEpvUzZ3b3krakszNVBCOUFDUDFQcllXR0diZjNYRwo1VngvZmRBSlNmdVFmL0NoZlRsa0kwQUYxUCsxUThhQU9BUXhKdU4ySVJxT0ErNlEwUTg2Vy9oZVFXbUdOUkI4CmxMcHQvWU9IV3NreHRqRDNmN3p1QXZZUkI1czFCZ3o2K2s1REF6d1pGNnlMMEtja1JpY3dFMHh3aisrZkcyeCsKdEpQb1AwdmliM0EzU0xySFhsRW5HbFdEL3ZSbkkrNkc1dFI2ZHJWbGcrcjhSRkFiYTJDc1VpTGFiM252Q2JqUQpDNG9xZWd1NklUNzk4R0thenBXbGw2b3M0SndQdFJnQzlvYS9FeklVanlWeStuRWhHU3pwSmlNQ0NZOS96b0daCmV1TGJ0M1lSdVVIaStiemludnNDQXdFQUFhT0NBbmd3Z2dKME1BNEdBMVVkRHdFQi93UUVBd0lGb0RBZEJnTlYKSFNVRUZqQVVCZ2dyQmdFRkJRY0RBUVlJS3dZQkJRVUhBd0l3REFZRFZSMFRBUUgvQkFJd0FEQWRCZ05WSFE0RQpGZ1FVRGZKNml2NlNoRlhzLzFrUTh5bmR1NGhTUEtrd0h3WURWUjBqQkJnd0ZvQVV3TXdEUnJsWUlNeGNjbkR6CjRTN0xJS2IxYURvd2R3WUlLd1lCQlFVSEFRRUVhekJwTURJR0NDc0dBUVVGQnpBQmhpWm9kSFJ3T2k4dmIyTnoKY0M1emRHY3RhVzUwTFhneExteGxkSE5sYm1OeWVYQjBMbTl5WnpBekJnZ3JCZ0VGQlFjd0FvWW5hSFIwY0RvdgpMMk5sY25RdWMzUm5MV2x1ZEMxNE1TNXNaWFJ6Wlc1amNubHdkQzV2Y21jdk1DWUdBMVVkRVFRZk1CMkNHMmhoCmIzaHBZVzVuTFdkamNDNXFaWFJ6ZEdGamEyVnlMbTVsZERCTUJnTlZIU0FFUlRCRE1BZ0dCbWVCREFFQ0FUQTMKQmdzckJnRUVBWUxmRXdFQkFUQW9NQ1lHQ0NzR0FRVUZCd0lCRmhwb2RIUndPaTh2WTNCekxteGxkSE5sYm1OeQplWEIwTG05eVp6Q0NBUVFHQ2lzR0FRUUIxbmtDQkFJRWdmVUVnZklBOEFCMkFMRE1nK1dsK1gxcnIzd0p6Q2hKCkJJY3F4K2lMRXl4alVMZkcvU2JoYkd4M0FBQUJjd1c3QXB3QUFBUURBRWN3UlFJaEFPai9nNm9ONjNTRnBqa00Ka3FmcjRDUlVzb0dWamZqQzN4MkRFdmR0RVZzNEFpQm05OTFzTHFHUzFJYksrM1VoemZzUDUvNTVjU2FpWkVPcwpwQmdVb1plb0l3QjJBTjJaTlB5bDV5U0F5VlpvZllFMG1RaEpza24zdFduWXg3eXJQMXpCODI1a0FBQUJjd1c3CkJJb0FBQVFEQUVjd1JRSWdVbTRDbW9hdDBIdTZaMUExcFRKbTc4WTRYaHZWcmJIQ3RYUUZaa0QweHZzQ0lRQ0IKbVBSTFFZS2RObUMyMXJLRW5hUjBBRjBZbS9ENEp6NjlhWTJUbEcwM1hqQU5CZ2txaGtpRzl3MEJBUXNGQUFPQwpBUUVBZHZoNFJuUGVaWEliazc3b2xjaTM0K0tZRmxCSUtDbFdUTkl3dXB5NlpGM0NYSlBzSjRQQWUvMGMzTVpaCkZSbDl4SHN2LzNESXZOaU5udkJSblRjdHJFMGp1V0cxYVlrWWIzaGRJMFVNcWlqUHNmc0doZW9LQnpRVDBoREcKRDFET0hPNXB5czQvNnp3NXk2TVMrdkoyVXY3aHlWem1PdldqaFp1c0xvUUZBcmpYY0ROY0puN3N2SkdOMXRFSgpZeUxHSk42SFpMV0xSeU8zdTBHYU9HQkk4SGRmc3JzbGVKaUk4b1ROaXdjaFZuekR1UUlLZFo0M040N0R5QlgwClpjTmplbElzeGtPSlhCUHJQVWJOaGltK1dNWjlicWxpUFZLamlhRUJFQ1BIaVRFK0Y2a3dkRkpkTktJZUVtL3UKR0JTRW5Zdmp2RWRJMzh4U1JWMXZDdDgxUUE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlFcXpDQ0FwT2dBd0lCQWdJUkFJdmhLZzVaUk8wOFZHUXg4SmRoVCtVd0RRWUpLb1pJaHZjTkFRRUxCUUF3CkdqRVlNQllHQTFVRUF3d1BSbUZyWlNCTVJTQlNiMjkwSUZneE1CNFhEVEUyTURVeU16SXlNRGMxT1ZvWERUTTIKTURVeU16SXlNRGMxT1Zvd0lqRWdNQjRHQTFVRUF3d1hSbUZyWlNCTVJTQkpiblJsY20xbFpHbGhkR1VnV0RFdwpnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEdFdLeVNEbjdyV1pjNWdnanozWkIwCjhqTzR4dGkzdXpJTmZENXNRN0xqN2h6ZXRVVCt3UW9iK2lYU1praG52eCtJdmRiWEY1L3l0OGFXUHBVS25QeW0Kb0x4c1lpSTVnUUJMeE5EekllYzBPSWFmbFdxQXIyOW03SjgrTk50QXBFTjhuWkZuZjNiaGVoWlc3QXhtUzFtMApablNzZEh3MEZ3K2JnaXhQZzJNUTlrOW9lZkZlcWErN0txZGx6NWJiclVZVjJ2b2x4aERGdG5JNE1oOEJpV0NOCnhESDFIaXpxK0dLQ2NIc2luRFpXdXJDcWRlci9hZkpCblFzK1NCU0w2TVZBcEh0K2QzNXpqQkQ5MmZPMkplNTYKZGhNZnpDZ09LWGVKMzQwV2hXM1RqRDF6cUxaWGVhQ3lVTlJuZk9tV1pWOG5FaHRIT0ZiVUNVN3IvS2tqTVpPOQpBZ01CQUFHamdlTXdnZUF3RGdZRFZSMFBBUUgvQkFRREFnR0dNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3CkhRWURWUjBPQkJZRUZNRE1BMGE1V0NETVhISnc4K0V1eXlDbTlXZzZNSG9HQ0NzR0FRVUZCd0VCQkc0d2JEQTAKQmdnckJnRUZCUWN3QVlZb2FIUjBjRG92TDI5amMzQXVjM1JuTFhKdmIzUXRlREV1YkdWMGMyVnVZM0o1Y0hRdQpiM0puTHpBMEJnZ3JCZ0VGQlFjd0FvWW9hSFIwY0RvdkwyTmxjblF1YzNSbkxYSnZiM1F0ZURFdWJHVjBjMlZ1ClkzSjVjSFF1YjNKbkx6QWZCZ05WSFNNRUdEQVdnQlRCSm5Ta2lrU2c1dm9nS05oY0k1cEZpQmg1NERBTkJna3EKaGtpRzl3MEJBUXNGQUFPQ0FnRUFCWVN1NElsK2ZJME1ZVTQyT1RtRWorMUhxUTVEdnlBZXlDQTZzR3VaZHdqRgpVR2VWT3YzTm5MeWZvZnVVT2pFYlk1aXJGQ0R0bnYrMGNrdWtVWk45bHo0UTJZaldHVXBXNFRUdTNpZVRzYUM5CkFGdkNTZ05ISnlXU1Z0V3ZCNVhEeHNxYXdsMUt6SHp6d3IxMzJiRjJydEd0YXpTcVZxSzlFMDdzR0hNQ2YrenAKRFFWRFZWR3RxWlBId1gzS3FVdGVmRTYyMWI4Ukk2VkNsNG9EMzBPbGY4cGp1ekc0SktCRlJGY2x6TFJqby9oNwpJa2tmalo4d0RhN2ZhT2pWWHg2bitlVVEyOWNJTUN6cjgvck5XSFM5cFlHR1FLSmlZMnhtVkM5aDEySDk5WHlmCnpXRTl2YjV6S1AzTVZHNm5lWDFoU2RvN1BFQWI5ZnFSaEhrcVZzcVV2SmxJUm12WHZWS1R3TkNQM2VDalJDQ0kKUFRBdmpWKzRuaTc4NmlYd3dGWU56OGwzUG1QTEN5UVhXR29obko4aUJtKzVuazdPMnluYVBWVzBVMlcrcHQydwpTVnV2ZERNNXpHdjJmOWx0TldVaVlaSEoxbW1POTdqU1kvNllmZE9VSDY2aVJ0UXREa0hCUmRrTkJzTWJEK0VtCjJUZ0JsZHRITlNKQmZCM3BtOUZibGdPY0owRlNXY1VEV0o3dk8wK05UWGxnclJvZlJUNnBWeXd6eFZvNmRORDAKV3pZbFRXZVVWc080MHhKcWhnVVFSRVI5WUxPTHhKME82QzhpMHhGeEFNS090U2RvZE1CM1JJd3Q3UkZRMHV5dApuNVo1TXFrWWhsTUkzSjF0UFJUcDFuRXQ5ZnlHc3BCT08wNWdpMTQ4UWFzcCszTitzdnFLb21vUWdsTm9BeFU9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K`)

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

			// Start a goroutine that will periodically check whether the CertificateRequest has been created
			// by the CLI command yet.
			// TODO: Once it has been created, set the `status.certificate` and `Ready` condition so that the `--fetch` part of the
			// command is able to proceed.
			if test.fetchCert {
				req := &cmapiv1alpha2.CertificateRequest{}
				go func() {
					err = wait.Poll(time.Second, 5 * time.Minute, func() (done bool, err error) {
						req, err = cmCl.CertmanagerV1alpha2().CertificateRequests(test.inputNamespace).Get(context.TODO(), test.inputArgs[0], metav1.GetOptions{})
						if err != nil {
							return false, nil
						}
						return true, nil
					})
					if err != nil {
						t.Fatal("timeout when waiting for CertificateRequest to be created")
					}

					// CR has been created, try update status
					readyCond := cmapiv1alpha2.CertificateRequestCondition{Type: cmapiv1alpha2.CertificateRequestConditionReady, Status: cmmeta.ConditionTrue}
					req.Status.Conditions = []cmapiv1alpha2.CertificateRequestCondition{readyCond}
					req.Status.Certificate = exampleCertificate
					_, err = cmCl.CertmanagerV1alpha2().CertificateRequests(test.inputNamespace).UpdateStatus(context.TODO(), req, metav1.UpdateOptions{})
					if err != nil {
						t.Fatal(err)
					}
				} ()
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
