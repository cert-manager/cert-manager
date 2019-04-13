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
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	reasonErrorPrivateKey = "PrivateKey"
)

// Issue will attempt to issue a new certificate from the Venafi Issuer.
// The control flow is as follows:
// - Attempt to retrieve the existing private key
// 		- If it does not exist, generate one
// - Generate a certificate template
// - Read the zone configuration from the Venafi server
// - Create a Venafi request based on the certificate template
// - Set defaults on the request based on the zone
// - Validate the request against the zone
// - Submit the request
// - Wait for the request to be fulfilled and the certificate to be available
func (v *Venafi) Issue(ctx context.Context, crt *v1alpha1.Certificate) (*issuer.IssueResponse, error) {
	v.Recorder.Event(crt, corev1.EventTypeNormal, "Issuing", "Requesting new certificate...")

	// Always generate a new private key, as some Venafi configurations mandate
	// unique private keys per issuance.
	signeeKey, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		klog.Errorf("Error generating private key %q for certificate: %v", crt.Spec.SecretName, err)
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "PrivateKeyError", "Error generating certificate private key: %v", err)
		// don't trigger a retry. An error from this function implies some
		// invalid input parameters, and retrying without updating the
		// resource will not help.
		return nil, nil
	}
	v.Recorder.Event(crt, corev1.EventTypeNormal, "GenerateKey", "Generated new private key")

	// extract the public component of the key
	signeePublicKey, err := pki.PublicKeyForPrivateKey(signeeKey)
	if err != nil {
		klog.Errorf("Error getting public key from private key: %v", err)
		return nil, err
	}

	// We build a x509.Certificate as the vcert library has support for converting
	// this into its own internal Certificate Request type.
	tmpl, err := pki.GenerateTemplate(crt)
	if err != nil {
		return nil, err
	}

	// TODO: we need some way to detect fields are defaulted on the template,
	// or otherwise move certificate/csr template defaulting into its own
	// function within the PKI package.
	// For now, we manually 'fix' the certificate template returned above
	if len(crt.Spec.Organization) == 0 {
		tmpl.Subject.Organization = []string{}
	}

	// set the PublicKey field on the certificate template so it can be checked
	// by the vcert library
	tmpl.PublicKey = signeePublicKey

	// Retrieve a copy of the Venafi zone.
	// This contains default values and policy control info that we can apply
	// and check against locally.
	zoneName := v.issuer.GetSpec().Venafi.Zone
	zoneCfg, err := v.client.ReadZoneConfiguration(zoneName)
	if err != nil {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "ReadZone", "Failed to read Venafi zone configuration: %v", err)
		return nil, err
	}

	//// Begin building Venafi certificate Request

	// Create a vcert Request structure
	vreq := newVRequest(tmpl)

	// Apply default values from the Venafi zone
	zoneCfg.UpdateCertificateRequest(vreq)
	err = zoneCfg.ValidateCertificateRequest(vreq)
	if err != nil {
		// TODO: set a certificate status condition instead of firing an event
		// in case this step is particularly chatty
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "Validate", "Failed to validate certificate against Venafi zone: %v", err)
		return nil, err
	}
	v.Recorder.Eventf(crt, corev1.EventTypeNormal, "Validate", "Validated certificate request against Venafi zone policy")

	// Generate the actual x509 CSR and set it on the vreq
	err = certificate.GenerateRequest(vreq, signeeKey)
	if err != nil {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "GenerateCSR", "Failed to generate a CSR for the certificate: %v", err)
		return nil, err
	}

	// certificate.GenerateRequest above sets the CSR field as der encoded bytes
	// however, the library actually requires this field to be PEM encoded.
	// We decode the DER bytes and run them through the PEM encoder and re-set the
	// field before actually calling RequestCertificate.
	// TODO: make this weird behaviour go away
	vreq.CSR = pem.EncodeToMemory(certificate.GetCertificateRequestPEMBlock(vreq.CSR))

	// We mark the request as having a user provided CSR, as we have manually
	// generated it in the lines above.
	// Setting this will prevent a new private key being generated by vcert.
	vreq.CsrOrigin = certificate.UserProvidedCSR
	// TODO: better set the timeout here. Right now, we'll block for this amount of time.
	vreq.Timeout = time.Minute * 5

	v.Recorder.Eventf(crt, corev1.EventTypeNormal, "Requesting", "Requesting certificate from Venafi server...")
	// Actually send a request to the Venafi server for a certificate.
	requestID, err := v.client.RequestCertificate(vreq, zoneName)
	if err != nil {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "Request", "Failed to request a certificate from Venafi: %v", err)
		return nil, err
	}

	// Set the PickupID so vcert does not have to look it up by the fingerprint
	vreq.PickupID = requestID

	// TODO: we probably need to check the error response here, as the certificate
	// may still be provisioning.
	// If so, we may *also* want to consider storing the pickup ID somewhere too
	// so we can attempt to retrieve the certificate on the next sync (i.e. wait
	// for issuance asynchronously).
	pemCollection, err := v.client.RetrieveCertificate(vreq)

	// Check some known error types
	if err, ok := err.(endpoint.ErrCertificatePending); ok {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "Retrieve", "Failed to retrieve a certificate from Venafi, still pending: %v", err)
		return nil, fmt.Errorf("Venafi certificate still pending: %v", err)
	}
	if err, ok := err.(endpoint.ErrRetrieveCertificateTimeout); ok {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "Retrieve", "Failed to retrieve a certificate from Venafi, timed out: %v", err)
		return nil, fmt.Errorf("Timed out waiting for certificate: %v", err)
	}
	if err != nil {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "Retrieve", "Failed to retrieve a certificate from Venafi: %v", err)
		return nil, err
	}
	v.Recorder.Eventf(crt, corev1.EventTypeNormal, "Retrieve", "Retrieved certificate from Venafi server")

	// Encode the private key ready to be saved
	pk, err := pki.EncodePrivateKey(signeeKey)
	if err != nil {
		return nil, err
	}

	// Construct the certificate chain and return the new keypair
	cs := append([]string{pemCollection.Certificate}, pemCollection.Chain...)
	chain := strings.Join(cs, "\n")
	return &issuer.IssueResponse{
		PrivateKey:  pk,
		Certificate: []byte(chain),
		// TODO: obtain CA certificate somehow
		// CA: []byte{},
	}, nil
}

func newVRequest(cert *x509.Certificate) *certificate.Request {
	req := certificate.NewRequest(cert)
	// overwrite entire Subject block
	req.Subject = cert.Subject
	return req
}
