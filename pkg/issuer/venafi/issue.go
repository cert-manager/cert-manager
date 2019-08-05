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
	"fmt"

	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	corev1 "k8s.io/api/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
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
	log := logf.FromContext(ctx, "venafi")
	log = logf.WithResource(log, crt)
	log = log.WithValues(logf.RelatedResourceNameKey, crt.Spec.SecretName, logf.RelatedResourceKindKey, "Secret")
	dbg := log.V(logf.DebugLevel)

	dbg.Info("issue method called")
	v.Recorder.Event(crt, corev1.EventTypeNormal, "Issuing", "Requesting new certificate...")

	// Always generate a new private key, as some Venafi configurations mandate
	// unique private keys per issuance.
	dbg.Info("generating new private key for certificate")
	signeeKey, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		log.Error(err, "failed to generate private key for certificate")
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "PrivateKeyError", "Error generating certificate private key: %v", err)
		// don't trigger a retry. An error from this function implies some
		// invalid input parameters, and retrying without updating the
		// resource will not help.
		return nil, nil
	}

	dbg.Info("generated new private key")
	v.Recorder.Event(crt, corev1.EventTypeNormal, "GenerateKey", "Generated new private key")

	pk, err := pki.EncodePKCS8PrivateKey(signeeKey)
	if err != nil {
		return nil, err
	}

	// We build a x509.Certificate as the vcert library has support for converting
	// this into its own internal Certificate Request type.
	dbg.Info("constructing certificate request template to submit to venafi")
	csr, err := pki.GenerateCSR(crt)
	if err != nil {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "GenerateCSR", "Failed to generate a CSR for the certificate: %v", err)
		return nil, err
	}

	csrPEM, err := pki.EncodeCSR(csr, signeeKey)
	if err != nil {
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "EncodeCSR", "Failed to PEM encode CSR for the certificate: %v", err)
		return nil, err
	}

	client, err := v.clientBuilder(v.resourceNamespace, v.secretsLister, v.issuer)
	if err != nil {
		v.Recorder.Eventf(v.issuer, corev1.EventTypeWarning, "FailedInit", "Failed to create Venafi client: %v", err)
		return nil, fmt.Errorf("error creating Venafi client: %s", err.Error())
	}

	cert, err := client.Sign(csrPEM)

	// Check some known error types
	if err, ok := err.(endpoint.ErrCertificatePending); ok {
		log.Error(err, "venafi certificate still in a pending state, the request will be retried")
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "Retrieve", "Failed to retrieve a certificate from Venafi, still pending: %v", err)
		return nil, fmt.Errorf("Venafi certificate still pending: %v", err)
	}
	if err, ok := err.(endpoint.ErrRetrieveCertificateTimeout); ok {
		log.Error(err, "timed out waiting for venafi certificate, the request will be retried")
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "Retrieve", "Failed to retrieve a certificate from Venafi, timed out: %v", err)
		return nil, fmt.Errorf("Timed out waiting for certificate: %v", err)
	}
	if err != nil {
		log.Error(err, "failed to obtain venafi certificate")
		v.Recorder.Eventf(crt, corev1.EventTypeWarning, "Retrieve", "Failed to retrieve a certificate from Venafi: %v", err)
		return nil, err
	}
	log.Info("successfully fetched signed certificate from venafi")
	v.Recorder.Eventf(crt, corev1.EventTypeNormal, "Retrieve", "Retrieved certificate from Venafi server")

	return &issuer.IssueResponse{
		PrivateKey:  pk,
		Certificate: cert,
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
