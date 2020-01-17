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
	"crypto/x509"
	"errors"
	"strings"
	"time"

	"github.com/Venafi/vcert/pkg/certificate"

	"github.com/jetstack/cert-manager/pkg/util/pki"
)

// This function sends a request to Venafi to for a signed certificate.
// The CSR will be decoded to be validated against the zone configuration policy.
// Upon the template being successfully defaulted and validated, the CSR will be sent, as is.
func (v *Venafi) Sign(csrPEM []byte, duration time.Duration) (cert []byte, err error) {
	// Retrieve a copy of the Venafi zone.
	// This contains default values and policy control info that we can apply
	// and check against locally.
	zoneCfg, err := v.client.ReadZoneConfiguration()
	if err != nil {
		return nil, err
	}

	tmpl, err := pki.GenerateTemplateFromCSRPEM(csrPEM, duration, false)
	if err != nil {
		return nil, err
	}

	// Create a vcert Request structure
	vreq := newVRequest(tmpl)

	// Apply default values from the Venafi zone
	zoneCfg.UpdateCertificateRequest(vreq)

	// Here we are validating the request using the current policy with
	// defaulting applied to the CSR. The CSR we send will not be defaulted
	// however, as this will be done again server side.
	err = zoneCfg.ValidateCertificateRequest(vreq)
	if err != nil {
		return nil, err
	}

	vreq.SetCSR(csrPEM)
	// Set options on the request
	vreq.CsrOrigin = certificate.UserProvidedCSR
	//// TODO: better set the timeout here. Right now, we'll block for this amount of time.
	vreq.Timeout = time.Minute * 5

	// Set the 'ObjectName' through the request friendly name. This is set in
	// order of precedence CN->DNS->URI.
	switch {
	case len(tmpl.Subject.CommonName) > 0:
		vreq.FriendlyName = tmpl.Subject.CommonName
		break
	case len(tmpl.DNSNames) > 0:
		vreq.FriendlyName = tmpl.DNSNames[0]
		break
	case len(tmpl.URIs) > 0:
		vreq.FriendlyName = tmpl.URIs[0].String()
		break
	default:
		return nil, errors.New(
			"certificate request contains no Common Name, DNS Name, nor URI SAN, at least one must be supplied to be used as the Venafi certificate objects name")
	}

	// Set the request CSR with the passed value
	if err := vreq.SetCSR(csrPEM); err != nil {
		return nil, err
	}

	// Send the certificate signing request to Venafi
	requestID, err := v.client.RequestCertificate(vreq)
	if err != nil {
		return nil, err
	}

	// Set the PickupID so vcert does not have to look it up by the fingerprint
	vreq.PickupID = requestID

	// Retrieve the certificate from request
	pemCollection, err := v.client.RetrieveCertificate(vreq)
	if err != nil {
		return nil, err
	}

	// Construct the certificate chain and return the new keypair
	cs := append([]string{pemCollection.Certificate}, pemCollection.Chain...)
	chain := strings.Join(cs, "\n")

	return []byte(chain), nil
}

func newVRequest(cert *x509.Certificate) *certificate.Request {
	req := certificate.NewRequest(cert)
	// overwrite entire Subject block
	req.Subject = cert.Subject
	return req
}
