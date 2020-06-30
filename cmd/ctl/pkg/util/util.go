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

package util

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapiv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

// FetchCertificateFromCR fetches the x509 certificate from a CR and stores the certificate in file specified by certFilename.
// Assumes CR is ready, otherwise returns error.
func FetchCertificateFromCR(cmClient cmclient.Interface,
	crName, crNamespace, certFileName string,
	ioStreams genericclioptions.IOStreams) error {
	req, err := cmClient.CertmanagerV1alpha2().CertificateRequests(crNamespace).Get(context.TODO(), crName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error when querying CertificateRequest: %w", err)
	}

	// If CR not ready yet, error
	if !apiutil.CertificateRequestHasCondition(req, cmapiv1alpha2.CertificateRequestCondition{
		Type:   cmapiv1alpha2.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		return errors.New("CertificateRequest is not ready yet, unable to fetch certificate")
	}

	// Store certificate to file
	err = ioutil.WriteFile(certFileName, req.Status.Certificate, 0600)
	if err != nil {
		return fmt.Errorf("error when writing certificate to file: %w", err)
	}

	fmt.Fprintf(ioStreams.Out, "Certificate has been stored in file %s\n", certFileName)
	return nil
}

// PollUntilCRIsReadyOrTimeOut waits until CertificateRequest has the Ready Condition set to true or until timeout occurs.
func PollUntilCRIsReadyOrTimeOut(client cmclient.Interface, req *cmapiv1alpha2.CertificateRequest, timeout, tick <-chan time.Time) error {
	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for CertificateRequest to be signed, retry later with fetch command")
		case <-tick:
			req, err := client.CertmanagerV1alpha2().CertificateRequests(req.Namespace).Get(context.TODO(), req.Name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("error when querying current status of CertificateRequest: %w", err)
			}
			if apiutil.CertificateRequestHasCondition(req, cmapiv1alpha2.CertificateRequestCondition{
				Type:   cmapiv1alpha2.CertificateRequestConditionReady,
				Status: cmmeta.ConditionTrue,
			}) {
				return nil
			}
		}
	}
}
