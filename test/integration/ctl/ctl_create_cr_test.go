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

package ctl

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/create/certificaterequest"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/integration/framework"
)

type CreateCRTest struct {
	inputFile      string
	inputArgs      []string
	inputNamespace string
	keyFilename    string
	certFilename   string
	fetchCert      bool
	timeout        time.Duration
	crStatus       cmapiv1.CertificateRequestStatus

	expRunErr          bool
	expErrMsg          string
	expNamespace       string
	expName            string
	expKeyFilename     string
	expCertFilename    string
	expCertFileContent []byte
}

// TestCtlCreateCRBeforeCRIsCreated tests the behaviour in the case where the command fails
// after the private key has been written to file and before the CR is successfully created.
// Achieved by trying to create two CRs with the same name, storing the private key to two different files.
func TestCtlCreateCRBeforeCRIsCreated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build clients
	kubernetesCl, _, cmCl, _ := framework.NewClients(t, config)

	testdataPath := getTestDataDir(t)

	const (
		cr5Name = "testcr-5"
		ns1     = "testns-1"
	)

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns1}}
	_, err := kubernetesCl.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]CreateCRTest{
		"path to file to store private key provided": {
			inputFile:      path.Join(testdataPath, "create_cr_cert_with_ns1.yaml"),
			inputArgs:      []string{cr5Name},
			inputNamespace: ns1,
			keyFilename:    "test.key",
			expRunErr:      true,
			expErrMsg:      fmt.Sprintf("error creating CertificateRequest: certificaterequests.cert-manager.io %q already exists", cr5Name),
			expKeyFilename: "test.key",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			streams, _, _, _ := genericclioptions.NewTestIOStreams()

			cleanUpFunc := setupPathForTest(t)
			defer cleanUpFunc()

			// Options to run create CR command
			opts := &certificaterequest.Options{
				InputFilename: test.inputFile,
				CertFileName:  test.certFilename,
				Factory: &factory.Factory{
					CMClient:         cmCl,
					RESTConfig:       config,
					Namespace:        test.inputNamespace,
					EnforceNamespace: test.inputNamespace != "",
				},
				IOStreams: streams,
			}

			err := opts.Run(ctx, test.inputArgs)
			if err != nil {
				t.Fatal("failed to set up test to fail after writing private key to file and during creating CR")
			}

			// By now we have created a CR already
			// Now we try to create another CR with the same name, but storing the private key somewhere else
			// This should break after writing private key to file and during creating CR
			opts.KeyFilename = test.keyFilename
			// Validating args and flags
			err = opts.Validate(test.inputArgs)
			if err != nil {
				t.Fatal(err)
			}

			// Run ctl create cr command with input options
			err = opts.Run(ctx, test.inputArgs)
			if err != nil {
				if !test.expRunErr {
					t.Errorf("got unexpected error when trying to create CR: %v", err)
				} else if err.Error() != test.expErrMsg {
					t.Errorf("got unexpected error when trying to create CR, expected: %v; actual: %v", test.expErrMsg, err)
				}
			} else {
				// got no error
				if test.expRunErr {
					t.Errorf("expected but got no error when creating CR")
				}
			}

			// Check the file where the private key is stored
			keyData, err := os.ReadFile(test.expKeyFilename)
			if err != nil {
				t.Errorf("error when reading file storing private key: %v", err)
			}
			_, err = pki.DecodePrivateKeyBytes(keyData)
			if err != nil {
				t.Errorf("invalid private key: %v", err)
			}

		})
	}
}

// TestCtlCreateCRSuccessful tests the behaviour in the case where the command successfully
// creates the CR, including the --fetch-certificate logic.
func TestCtlCreateCRSuccessful(t *testing.T) {
	rootCtx, cancelRoot := context.WithTimeout(context.Background(), time.Second*200)
	defer cancelRoot()

	config, stopFn := framework.RunControlPlane(t, rootCtx)
	defer stopFn()

	// Build clients
	kubernetesCl, _, cmCl, _ := framework.NewClients(t, config)

	testdataPath := getTestDataDir(t)

	const (
		cr1Name = "testcr-1"
		cr2Name = "testcr-2"
		cr5Name = "testcr-5"
		cr6Name = "testcr-6"
		cr7Name = "testcr-7"
		ns1     = "testns-1"
	)
	exampleCertificate := []byte(`LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZUekNDQkRlZ0F3SUJBZ0lUQVBwOWhMUit2ODF2UTdpZSt6emxTMWY5MFRBTkJna3Foa2lHOXcwQkFRc0YKQURBaU1TQXdIZ1lEVlFRRERCZEdZV3RsSUV4RklFbHVkR1Z5YldWa2FXRjBaU0JZTVRBZUZ3MHlNREEyTXpBeApNelUyTkRoYUZ3MHlNREE1TWpneE16VTJORGhhTUNZeEpEQWlCZ05WQkFNVEcyaGhiM2hwWVc1bkxXZGpjQzVxClpYUnpkR0ZqYTJWeUxtNWxkRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFOTjIKTS9zZGtPazgvenJLbXNvMEE1SmxoUjRTQU9pTVhiWGZleEpvUzZ3b3krakszNVBCOUFDUDFQcllXR0diZjNYRwo1VngvZmRBSlNmdVFmL0NoZlRsa0kwQUYxUCsxUThhQU9BUXhKdU4ySVJxT0ErNlEwUTg2Vy9oZVFXbUdOUkI4CmxMcHQvWU9IV3NreHRqRDNmN3p1QXZZUkI1czFCZ3o2K2s1REF6d1pGNnlMMEtja1JpY3dFMHh3aisrZkcyeCsKdEpQb1AwdmliM0EzU0xySFhsRW5HbFdEL3ZSbkkrNkc1dFI2ZHJWbGcrcjhSRkFiYTJDc1VpTGFiM252Q2JqUQpDNG9xZWd1NklUNzk4R0thenBXbGw2b3M0SndQdFJnQzlvYS9FeklVanlWeStuRWhHU3pwSmlNQ0NZOS96b0daCmV1TGJ0M1lSdVVIaStiemludnNDQXdFQUFhT0NBbmd3Z2dKME1BNEdBMVVkRHdFQi93UUVBd0lGb0RBZEJnTlYKSFNVRUZqQVVCZ2dyQmdFRkJRY0RBUVlJS3dZQkJRVUhBd0l3REFZRFZSMFRBUUgvQkFJd0FEQWRCZ05WSFE0RQpGZ1FVRGZKNml2NlNoRlhzLzFrUTh5bmR1NGhTUEtrd0h3WURWUjBqQkJnd0ZvQVV3TXdEUnJsWUlNeGNjbkR6CjRTN0xJS2IxYURvd2R3WUlLd1lCQlFVSEFRRUVhekJwTURJR0NDc0dBUVVGQnpBQmhpWm9kSFJ3T2k4dmIyTnoKY0M1emRHY3RhVzUwTFhneExteGxkSE5sYm1OeWVYQjBMbTl5WnpBekJnZ3JCZ0VGQlFjd0FvWW5hSFIwY0RvdgpMMk5sY25RdWMzUm5MV2x1ZEMxNE1TNXNaWFJ6Wlc1amNubHdkQzV2Y21jdk1DWUdBMVVkRVFRZk1CMkNHMmhoCmIzaHBZVzVuTFdkamNDNXFaWFJ6ZEdGamEyVnlMbTVsZERCTUJnTlZIU0FFUlRCRE1BZ0dCbWVCREFFQ0FUQTMKQmdzckJnRUVBWUxmRXdFQkFUQW9NQ1lHQ0NzR0FRVUZCd0lCRmhwb2RIUndPaTh2WTNCekxteGxkSE5sYm1OeQplWEIwTG05eVp6Q0NBUVFHQ2lzR0FRUUIxbmtDQkFJRWdmVUVnZklBOEFCMkFMRE1nK1dsK1gxcnIzd0p6Q2hKCkJJY3F4K2lMRXl4alVMZkcvU2JoYkd4M0FBQUJjd1c3QXB3QUFBUURBRWN3UlFJaEFPai9nNm9ONjNTRnBqa00Ka3FmcjRDUlVzb0dWamZqQzN4MkRFdmR0RVZzNEFpQm05OTFzTHFHUzFJYksrM1VoemZzUDUvNTVjU2FpWkVPcwpwQmdVb1plb0l3QjJBTjJaTlB5bDV5U0F5VlpvZllFMG1RaEpza24zdFduWXg3eXJQMXpCODI1a0FBQUJjd1c3CkJJb0FBQVFEQUVjd1JRSWdVbTRDbW9hdDBIdTZaMUExcFRKbTc4WTRYaHZWcmJIQ3RYUUZaa0QweHZzQ0lRQ0IKbVBSTFFZS2RObUMyMXJLRW5hUjBBRjBZbS9ENEp6NjlhWTJUbEcwM1hqQU5CZ2txaGtpRzl3MEJBUXNGQUFPQwpBUUVBZHZoNFJuUGVaWEliazc3b2xjaTM0K0tZRmxCSUtDbFdUTkl3dXB5NlpGM0NYSlBzSjRQQWUvMGMzTVpaCkZSbDl4SHN2LzNESXZOaU5udkJSblRjdHJFMGp1V0cxYVlrWWIzaGRJMFVNcWlqUHNmc0doZW9LQnpRVDBoREcKRDFET0hPNXB5czQvNnp3NXk2TVMrdkoyVXY3aHlWem1PdldqaFp1c0xvUUZBcmpYY0ROY0puN3N2SkdOMXRFSgpZeUxHSk42SFpMV0xSeU8zdTBHYU9HQkk4SGRmc3JzbGVKaUk4b1ROaXdjaFZuekR1UUlLZFo0M040N0R5QlgwClpjTmplbElzeGtPSlhCUHJQVWJOaGltK1dNWjlicWxpUFZLamlhRUJFQ1BIaVRFK0Y2a3dkRkpkTktJZUVtL3UKR0JTRW5Zdmp2RWRJMzh4U1JWMXZDdDgxUUE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlFcXpDQ0FwT2dBd0lCQWdJUkFJdmhLZzVaUk8wOFZHUXg4SmRoVCtVd0RRWUpLb1pJaHZjTkFRRUxCUUF3CkdqRVlNQllHQTFVRUF3d1BSbUZyWlNCTVJTQlNiMjkwSUZneE1CNFhEVEUyTURVeU16SXlNRGMxT1ZvWERUTTIKTURVeU16SXlNRGMxT1Zvd0lqRWdNQjRHQTFVRUF3d1hSbUZyWlNCTVJTQkpiblJsY20xbFpHbGhkR1VnV0RFdwpnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEdFdLeVNEbjdyV1pjNWdnanozWkIwCjhqTzR4dGkzdXpJTmZENXNRN0xqN2h6ZXRVVCt3UW9iK2lYU1praG52eCtJdmRiWEY1L3l0OGFXUHBVS25QeW0Kb0x4c1lpSTVnUUJMeE5EekllYzBPSWFmbFdxQXIyOW03SjgrTk50QXBFTjhuWkZuZjNiaGVoWlc3QXhtUzFtMApablNzZEh3MEZ3K2JnaXhQZzJNUTlrOW9lZkZlcWErN0txZGx6NWJiclVZVjJ2b2x4aERGdG5JNE1oOEJpV0NOCnhESDFIaXpxK0dLQ2NIc2luRFpXdXJDcWRlci9hZkpCblFzK1NCU0w2TVZBcEh0K2QzNXpqQkQ5MmZPMkplNTYKZGhNZnpDZ09LWGVKMzQwV2hXM1RqRDF6cUxaWGVhQ3lVTlJuZk9tV1pWOG5FaHRIT0ZiVUNVN3IvS2tqTVpPOQpBZ01CQUFHamdlTXdnZUF3RGdZRFZSMFBBUUgvQkFRREFnR0dNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3CkhRWURWUjBPQkJZRUZNRE1BMGE1V0NETVhISnc4K0V1eXlDbTlXZzZNSG9HQ0NzR0FRVUZCd0VCQkc0d2JEQTAKQmdnckJnRUZCUWN3QVlZb2FIUjBjRG92TDI5amMzQXVjM1JuTFhKdmIzUXRlREV1YkdWMGMyVnVZM0o1Y0hRdQpiM0puTHpBMEJnZ3JCZ0VGQlFjd0FvWW9hSFIwY0RvdkwyTmxjblF1YzNSbkxYSnZiM1F0ZURFdWJHVjBjMlZ1ClkzSjVjSFF1YjNKbkx6QWZCZ05WSFNNRUdEQVdnQlRCSm5Ta2lrU2c1dm9nS05oY0k1cEZpQmg1NERBTkJna3EKaGtpRzl3MEJBUXNGQUFPQ0FnRUFCWVN1NElsK2ZJME1ZVTQyT1RtRWorMUhxUTVEdnlBZXlDQTZzR3VaZHdqRgpVR2VWT3YzTm5MeWZvZnVVT2pFYlk1aXJGQ0R0bnYrMGNrdWtVWk45bHo0UTJZaldHVXBXNFRUdTNpZVRzYUM5CkFGdkNTZ05ISnlXU1Z0V3ZCNVhEeHNxYXdsMUt6SHp6d3IxMzJiRjJydEd0YXpTcVZxSzlFMDdzR0hNQ2YrenAKRFFWRFZWR3RxWlBId1gzS3FVdGVmRTYyMWI4Ukk2VkNsNG9EMzBPbGY4cGp1ekc0SktCRlJGY2x6TFJqby9oNwpJa2tmalo4d0RhN2ZhT2pWWHg2bitlVVEyOWNJTUN6cjgvck5XSFM5cFlHR1FLSmlZMnhtVkM5aDEySDk5WHlmCnpXRTl2YjV6S1AzTVZHNm5lWDFoU2RvN1BFQWI5ZnFSaEhrcVZzcVV2SmxJUm12WHZWS1R3TkNQM2VDalJDQ0kKUFRBdmpWKzRuaTc4NmlYd3dGWU56OGwzUG1QTEN5UVhXR29obko4aUJtKzVuazdPMnluYVBWVzBVMlcrcHQydwpTVnV2ZERNNXpHdjJmOWx0TldVaVlaSEoxbW1POTdqU1kvNllmZE9VSDY2aVJ0UXREa0hCUmRrTkJzTWJEK0VtCjJUZ0JsZHRITlNKQmZCM3BtOUZibGdPY0owRlNXY1VEV0o3dk8wK05UWGxnclJvZlJUNnBWeXd6eFZvNmRORDAKV3pZbFRXZVVWc080MHhKcWhnVVFSRVI5WUxPTHhKME82QzhpMHhGeEFNS090U2RvZE1CM1JJd3Q3UkZRMHV5dApuNVo1TXFrWWhsTUkzSjF0UFJUcDFuRXQ5ZnlHc3BCT08wNWdpMTQ4UWFzcCszTitzdnFLb21vUWdsTm9BeFU9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K`)

	// Create Namespace
	_, err := kubernetesCl.CoreV1().Namespaces().Create(rootCtx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns1}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]CreateCRTest{
		"v1 Certificate given": {
			inputFile:      path.Join(testdataPath, "create_cr_cert_with_ns1.yaml"),
			inputArgs:      []string{cr1Name},
			inputNamespace: ns1,
			keyFilename:    "",
			expRunErr:      false,
			expNamespace:   ns1,
			expName:        cr1Name,
			expKeyFilename: cr1Name + ".key",
		},
		"v1alpha3 Certificate given": {
			inputFile:      path.Join(testdataPath, "create_cr_v1alpha3_cert_with_ns1.yaml"),
			inputArgs:      []string{cr2Name},
			inputNamespace: ns1,
			keyFilename:    "",
			expRunErr:      false,
			expNamespace:   ns1,
			expName:        cr2Name,
			expKeyFilename: cr2Name + ".key",
		},
		"path to file to store private key provided": {
			inputFile:      path.Join(testdataPath, "create_cr_cert_with_ns1.yaml"),
			inputArgs:      []string{cr5Name},
			inputNamespace: ns1,
			keyFilename:    "test.key",
			expRunErr:      false,
			expNamespace:   ns1,
			expName:        cr5Name,
			expKeyFilename: "test.key",
		},
		"fetch flag set and CR will be ready and status.certificate set": {
			inputFile:      path.Join(testdataPath, "create_cr_cert_with_ns1.yaml"),
			inputArgs:      []string{cr6Name},
			inputNamespace: ns1,
			keyFilename:    "",
			fetchCert:      true,
			timeout:        5 * time.Minute,
			crStatus: cmapiv1.CertificateRequestStatus{
				Conditions: []cmapiv1.CertificateRequestCondition{
					{Type: cmapiv1.CertificateRequestConditionReady, Status: cmmeta.ConditionTrue},
				},
				Certificate: exampleCertificate,
			},
			expRunErr:          false,
			expNamespace:       ns1,
			expName:            cr6Name,
			expKeyFilename:     cr6Name + ".key",
			expCertFilename:    cr6Name + ".crt",
			expCertFileContent: exampleCertificate,
		},
		"fetch flag set and CR will be ready but status.certificate empty": {
			inputFile:      path.Join(testdataPath, "create_cr_cert_with_ns1.yaml"),
			inputArgs:      []string{cr7Name},
			inputNamespace: ns1,
			keyFilename:    "",
			fetchCert:      true,
			timeout:        5 * time.Second,
			crStatus: cmapiv1.CertificateRequestStatus{
				Conditions: []cmapiv1.CertificateRequestCondition{
					{Type: cmapiv1.CertificateRequestConditionReady, Status: cmmeta.ConditionTrue},
				},
			},
			expRunErr:          true,
			expErrMsg:          "error when waiting for CertificateRequest to be signed: timed out waiting for the condition",
			expNamespace:       ns1,
			expName:            cr7Name,
			expKeyFilename:     cr7Name + ".key",
			expCertFilename:    cr7Name + ".crt",
			expCertFileContent: exampleCertificate,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(rootCtx, time.Second*20)
			defer cancel()

			streams, _, _, _ := genericclioptions.NewTestIOStreams()

			cleanUpFunc := setupPathForTest(t)
			defer cleanUpFunc()

			// Options to run create CR command
			opts := &certificaterequest.Options{
				Factory: &factory.Factory{
					CMClient:         cmCl,
					RESTConfig:       config,
					Namespace:        test.inputNamespace,
					EnforceNamespace: test.inputNamespace != "",
				},
				IOStreams:     streams,
				InputFilename: test.inputFile,
				KeyFilename:   test.keyFilename,
				CertFileName:  test.certFilename,
				FetchCert:     test.fetchCert,
				Timeout:       test.timeout,
			}

			// Validating args and flags
			err := opts.Validate(test.inputArgs)
			if err != nil {
				t.Fatal(err)
			}

			if test.fetchCert {
				req := &cmapiv1.CertificateRequest{}
				// Start a goroutine that will periodically check whether the CertificateRequest has been created
				// by the CLI command yet.
				// Once it has been created, set the `status.certificate` and `Ready` condition so that the `--fetch-certificate`
				// part of the command is able to proceed.
				errCh := make(chan error)
				pollCtx, cancelPoll := context.WithCancel(ctx)
				defer func() {
					cancelPoll()
					err := <-errCh
					if err != nil {
						t.Fatal(err)
					}
				}()
				go func() {
					defer close(errCh)
					err = wait.PollImmediateUntil(time.Second, func() (done bool, err error) {
						req, err = cmCl.CertmanagerV1().CertificateRequests(test.inputNamespace).Get(pollCtx, test.inputArgs[0], metav1.GetOptions{})
						if err != nil {
							return false, nil
						}
						return true, nil
					}, pollCtx.Done())
					if err != nil {
						errCh <- fmt.Errorf("timeout when waiting for CertificateRequest to be created, error: %v", err)
						return
					}

					// CR has been created, try update status
					req.Status.Conditions = test.crStatus.Conditions
					req.Status.Certificate = test.crStatus.Certificate
					req, err = cmCl.CertmanagerV1().CertificateRequests(test.inputNamespace).UpdateStatus(pollCtx, req, metav1.UpdateOptions{})
					if err != nil {
						errCh <- err
					}
				}()
			}

			// Run ctl create cr command with input options
			err = opts.Run(ctx, test.inputArgs)
			if err != nil {
				if !test.expRunErr {
					t.Errorf("got unexpected error when trying to create CR: %v", err)
				} else if err.Error() != test.expErrMsg {
					t.Errorf("got unexpected error when trying to create CR, expected: %v; actual: %v", test.expErrMsg, err)
				}
			} else {
				// got no error
				if test.expRunErr {
					t.Errorf("expected but got no error when creating CR")
				}
			}

			// Check the file where the private key is stored
			keyData, err := os.ReadFile(test.expKeyFilename)
			if err != nil {
				t.Errorf("error when reading file storing private key: %v", err)
			}
			_, err = pki.DecodePrivateKeyBytes(keyData)
			if err != nil {
				t.Errorf("invalid private key: %v", err)
			}

			// Finished creating CR, check if everything is expected
			crName := test.inputArgs[0]
			gotCr, err := cmCl.CertmanagerV1().CertificateRequests(test.inputNamespace).Get(ctx, crName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if gotCr.Name != test.expName {
				t.Errorf("CR created has unexpected Name, expected: %s, actual: %s", test.expName, gotCr.Name)
			}

			if gotCr.Namespace != test.expNamespace {
				t.Errorf("CR created in unexpected Namespace, expected: %s, actual: %s", test.expNamespace, gotCr.Namespace)
			}

			// If applicable, check the file where the certificate is stored
			// If the expected error message is the one below, we skip checking
			// because no certificate will have been written to file
			if test.fetchCert && test.expErrMsg != "error when waiting for CertificateRequest to be signed: timed out waiting for the condition" {
				certData, err := os.ReadFile(test.expCertFilename)
				if err != nil {
					t.Errorf("error when reading file storing private key: %v", err)
				}

				if !bytes.Equal(test.expCertFileContent, certData) {
					t.Errorf("certificate written to file is wrong, expected: %s,\nactual: %s", test.expCertFileContent, certData)
				}
			}
		})
	}
}

func getTestDataDir(t *testing.T) string {
	testWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return path.Join(testWorkingDirectory, "testdata")
}

// setupPathForTest sets up a tmp directory and cd into it for tests as the command being tested creates files
// in the local directory.
// Returns a cleanup function which will change cd back to original working directory and remove the tmp directory.
func setupPathForTest(t *testing.T) func() {
	workingDirectoryBeforeTest, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// Create tmp directory and cd into it to store private key files
	tmpDir, err := os.MkdirTemp("", "tmp-ctl-test-*")
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
