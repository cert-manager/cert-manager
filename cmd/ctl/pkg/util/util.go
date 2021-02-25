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

package util

import (
	"errors"
	"fmt"
	"io/ioutil"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// FetchCertificateFromCR fetches the x509 certificate from a CR and stores the certificate in file specified by certFilename.
// Assumes CR is ready, otherwise returns error.
func FetchCertificateFromCR(req *cmapi.CertificateRequest, certFileName string) error {
	// If CR not ready yet, error
	if !apiutil.CertificateRequestHasCondition(req, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) || len(req.Status.Certificate) == 0 {
		return errors.New("CertificateRequest is not ready yet, unable to fetch certificate")
	}

	// Store certificate to file
	err := ioutil.WriteFile(certFileName, req.Status.Certificate, 0600)
	if err != nil {
		return fmt.Errorf("error when writing certificate to file: %w", err)
	}

	return nil
}
