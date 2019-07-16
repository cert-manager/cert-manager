/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package step

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/smallstep/certificates/api"
	corev1 "k8s.io/api/core/v1"
)

// Sign attempts to issue a certificate as described by the CertificateRequest
// resource given.
func (s *Step) Sign(ctx context.Context, cr *certmanager.CertificateRequest) (*issuer.IssueResponse, error) {
	// Get root certificate(s)
	roots, err := s.provisioner.Roots()
	if err != nil {
		s.Recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error retrieving root certificates: %v", err)
		return nil, err
	}

	// Encode root certificates
	var caPem []byte
	for _, root := range roots.Certificates {
		b, err := pki.EncodeX509(root.Certificate)
		if err != nil {
			s.Recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error encoding root certificates: %v", err)
			return nil, err
		}
		caPem = append(caPem, b...)
	}

	block, rest := pem.Decode(cr.Spec.CSRPEM)
	if block == nil || len(rest) > 0 {
		return nil, fmt.Errorf("unexpected CSR PEM on sign request")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM is not a certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate request: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("error checking certificate request signature: %v", err)
	}

	var sans []string
	for _, dns := range csr.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}

	token, err := s.provisioner.Token(csr.Subject.CommonName, sans...)
	if err != nil {
		s.Recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error creating signing token: %v", err)
		return nil, err
	}

	var notAfter api.TimeDuration
	if cr.Spec.Duration != nil {
		notAfter.SetDuration(cr.Spec.Duration.Duration)
	}

	resp, err := s.provisioner.Sign(&api.SignRequest{
		CsrPEM: api.CertificateRequest{
			CertificateRequest: csr,
		},
		OTT:      token,
		NotAfter: notAfter,
	})
	if err != nil {
		s.Recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error signing certificate: %v", err)
		return nil, err
	}

	// Encode server certificate with the intermediate
	certPem, err := pki.EncodeX509(resp.ServerPEM.Certificate)
	if err != nil {
		s.Recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error encoding certificate: %v", err)
		return nil, err
	}
	chainPem, err := pki.EncodeX509(resp.CaPEM.Certificate)
	if err != nil {
		s.Recorder.Eventf(cr, corev1.EventTypeWarning, "ErrorSigning", "Error encoding intermediate certificate: %v", err)
		return nil, err
	}
	certPem = append(certPem, chainPem...)

	// Note that PrivateKey is not available.
	return &issuer.IssueResponse{
		Certificate: certPem,
		CA:          caPem,
	}, nil
}
