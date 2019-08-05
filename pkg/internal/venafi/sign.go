/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package venafi

import (
	"strings"
	"time"

	"github.com/Venafi/vcert/pkg/certificate"
)

func (v *Venafi) Sign(csrPEM []byte) (cert []byte, err error) {
	vreq := new(certificate.Request)

	// Retrieve a copy of the Venafi zone.
	// This contains default values and policy control info that we can apply
	// and check against locally.
	//dbg.Info("reading venafi zone configuration")
	zoneCfg, err := v.client.ReadZoneConfiguration()
	if err != nil {
		return nil, err
	}

	// Apply default values from the Venafi zone
	//dbg.Info("applying default venafi zone values to request")
	zoneCfg.UpdateCertificateRequest(vreq)

	if err := vreq.SetCSR(csrPEM); err != nil {
		return nil, err
	}

	vreq.CsrOrigin = certificate.UserProvidedCSR
	vreq.Timeout = time.Minute * 5

	//dbg.Info("submitting generated CSR to venafi")
	requestID, err := v.client.RequestCertificate(vreq)
	if err != nil {
		return nil, err
	}

	//dbg.Info("successfully submitted request. attempting to pickup certificate from venafi server...")
	// Set the PickupID so vcert does not have to look it up by the fingerprint
	vreq.PickupID = requestID

	pemCollection, err := v.client.RetrieveCertificate(vreq)
	if err != nil {
		return nil, err
	}

	// Construct the certificate chain and return the new keypair
	cs := append([]string{pemCollection.Certificate}, pemCollection.Chain...)
	chain := strings.Join(cs, "\n")

	return []byte(chain), nil
}
