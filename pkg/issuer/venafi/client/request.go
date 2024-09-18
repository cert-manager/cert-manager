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

package client

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/venafi/tpp"

	"github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/api"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// ErrCustomFieldsType provides a common error structure for an invalid Venafi custom field type
type ErrCustomFieldsType struct {
	Type api.CustomFieldType
}

func (err ErrCustomFieldsType) Error() string {
	return fmt.Sprintf("certificate request contains an invalid Venafi custom fields type: %q", err.Type)
}

var ErrorMissingSubject = errors.New("Certificate requests submitted to Venafi issuers must have the 'commonName' field or at least one other subject field set.")

// This function sends a request to Venafi to for a signed certificate.
// The CSR will be decoded to be validated against the zone configuration policy.
// Upon the template being successfully defaulted and validated, the CSR will be sent, as is.
// It will return a pickup ID which can be used with RetrieveCertificate to get the certificate
func (v *Venafi) RequestCertificate(csrPEM []byte, duration time.Duration, customFields []api.CustomField) (string, error) {
	vreq, err := v.buildVReq(csrPEM, duration, customFields)
	if err != nil {
		return "", err
	}

	// If the connector is TPP, we unconditionally reset any prior failed enrollment
	// so that we don't get stuck with "Fix any errors, and then click Retry."
	// (60% of the time) or "WebSDK CertRequest" (40% of the time).
	//
	// It would be preferable to only reset when necessary to avoid the extra
	// call. We tried that in https://github.com/Venafi/vcert/pull/269. It turns
	// out that calling "request" followed by "reset(restart=true)" causes a
	// race in TPP.
	//
	// Unconditionally resetting isn't optimal, but "reset(restart=false)" is
	// lightweight. We haven't verified that it doesn't slow things down on
	// large TPP instances.
	//
	// Note that resetting won't affect the existing certificate if one was
	// already issued.
	if v.tppClient != nil {
		// We can't use the instrumented v.vcertClient because its concrete
		// value is `instrumentedConnector`, which doesn't give access to the
		// *tpp.Connector it wraps. Also, `instrumentedConnector` doesn't
		// support `ResetCertificate`.
		err := v.tppClient.ResetCertificate(vreq, false)
		notFoundErr := &tpp.ErrCertNotFound{}
		if err != nil && !errors.As(err, &notFoundErr) {
			return "", err
		}
	}

	return v.vcertClient.RequestCertificate(vreq)
}

func (v *Venafi) RetrieveCertificate(pickupID string, csrPEM []byte, duration time.Duration, customFields []api.CustomField) ([]byte, error) {
	vreq, err := v.buildVReq(csrPEM, duration, customFields)
	if err != nil {
		return nil, err
	}

	vreq.PickupID = pickupID
	vreq.Timeout = time.Second * 60

	// Retrieve the certificate from request
	pemCollection, err := v.vcertClient.RetrieveCertificate(vreq)
	if err != nil {
		return nil, err
	}

	// Construct the certificate chain and return the new keypair
	cs := append([]string{pemCollection.Certificate}, pemCollection.Chain...)
	chain := strings.Join(cs, "\n")

	return []byte(chain), nil
}

func (v *Venafi) buildVReq(csrPEM []byte, duration time.Duration, customFields []api.CustomField) (*certificate.Request, error) {
	// Retrieve a copy of the Venafi zone.
	// This contains default values and policy control info that we can apply
	// and check against locally.
	zoneCfg, err := v.vcertClient.ReadZoneConfiguration()
	if err != nil {
		return nil, err
	}

	tmpl, err := pki.CertificateTemplateFromCSRPEM(csrPEM)
	if err != nil {
		return nil, err
	}

	if tmpl.Subject.String() == "" {
		return nil, ErrorMissingSubject
	}

	// Create a vcert Request structure
	vreq := newVRequest(tmpl, duration)

	// Convert over custom fields from our struct type to venafi's
	vfields, err := convertCustomFieldsToVcert(customFields)
	if err != nil {
		return nil, err
	}
	vreq.CustomFields = append(vreq.CustomFields, vfields...)

	// Apply default values from the Venafi zone
	zoneCfg.UpdateCertificateRequest(vreq)

	// Here we are validating the request using the current policy with
	// defaulting applied to the CSR. The CSR we send will not be defaulted
	// however, as this will be done again server side.
	err = zoneCfg.ValidateCertificateRequest(vreq)
	if err != nil {
		return nil, err
	}

	friendlyName, err := getVcertFriendlyName(tmpl)
	if err != nil {
		return nil, err
	}
	vreq.FriendlyName = friendlyName

	// Set options on the request
	vreq.CsrOrigin = certificate.UserProvidedCSR

	// Set the request CSR with the passed value
	if err := vreq.SetCSR(csrPEM); err != nil {
		return nil, err
	}

	return vreq, nil
}

func convertCustomFieldsToVcert(customFields []api.CustomField) ([]certificate.CustomField, error) {
	var out []certificate.CustomField
	if len(customFields) > 0 {
		for _, field := range customFields {
			var fieldType certificate.CustomFieldType
			switch field.Type {
			case api.CustomFieldTypePlain, "":
				fieldType = certificate.CustomFieldPlain
			default:
				return nil, ErrCustomFieldsType{Type: field.Type}
			}

			out = append(out, certificate.CustomField{
				Type:  fieldType,
				Name:  field.Name,
				Value: field.Value,
			})
		}
	}

	return out, nil
}

func newVRequest(cert *x509.Certificate, duration time.Duration) *certificate.Request {
	req := certificate.NewRequest(cert)

	req.ValidityDuration = &duration
	req.IssuerHint = util.IssuerHintAllIssuers
	req.ChainOption = certificate.ChainOptionRootLast

	// overwrite entire Subject block
	req.Subject = cert.Subject
	// Add cert-manager origin tag
	req.CustomFields = []certificate.CustomField{
		{
			Type:  certificate.CustomFieldOrigin,
			Value: "cert-manager",
		},
	}
	return req
}

func getVcertFriendlyName(crt *x509.Certificate) (string, error) {
	// Set the 'ObjectName' through the vcert friendly name. This is set in
	// order of precedence CN->DNS->URI.
	switch {
	case len(crt.Subject.CommonName) > 0:
		return crt.Subject.CommonName, nil
	case len(crt.DNSNames) > 0:
		return crt.DNSNames[0], nil
	case len(crt.URIs) > 0:
		return crt.URIs[0].String(), nil
	case len(crt.EmailAddresses) > 0:
		return crt.EmailAddresses[0], nil
	case len(crt.IPAddresses) > 0:
		return crt.IPAddresses[0].String(), nil
	default:
		return "", errors.New("certificate request contains no Common Name, DNS Name, nor URI SAN, at least one must be supplied to be used as the Venafi certificate objects name")
	}
}
