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

package step

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/smallstep/certificates/api"
	corev1 "k8s.io/api/core/v1"
)

// Issue attempts to issue a certificate as described by the certificate
// resource given
func (s *Step) Issue(ctx context.Context, crt *certmanager.Certificate) (*issuer.IssueResponse, error) {
	var signFlow bool

	// Get previous key pair if it exists.
	// If the key pair is already in a secret we will do a renew flow.
	// If not a sign flow.
	cert, key, err := kube.SecretTLSKeyPair(ctx, s.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if err != nil {
		signFlow = true
		key, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			s.Recorder.Eventf(crt, corev1.EventTypeWarning, "PrivateKeyError", "Error generating certificate private key: %v", err)
			// don't trigger a retry. An error from this function implies some
			// invalid input parameters, and retrying without updating the
			// resource will not help.
			return nil, nil
		}
	}

	// If expired force sign flow
	if crt.Status.NotAfter != nil && crt.Status.NotAfter.Time.Before(time.Now()) {
		signFlow = true
	}

	keyPem, err := pki.EncodePrivateKey(key, crt.Spec.KeyEncoding)
	if err != nil {
		s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorPrivateKey", "Error encoding private key: %v", err)
		return nil, err
	}

	// Get root certificate(s)
	roots, err := s.provisioner.Roots()
	if err != nil {
		s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error retrieving root certificates: %v", err)
		return nil, err
	}

	// Encode root certificates
	var caPem []byte
	rootCA := x509.NewCertPool()
	for _, root := range roots.Certificates {
		b, err := pki.EncodeX509(root.Certificate)
		if err != nil {
			s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error encoding root certificates: %v", err)
			return nil, err
		}
		caPem = append(caPem, b...)
		rootCA.AddCert(root.Certificate)
	}

	var resp *api.SignResponse
	if signFlow {
		template, err := pki.GenerateCSR(s.issuer, crt)
		if err != nil {
			s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error creating certificate signing request: %v", err)
			return nil, err
		}

		csrBytes, err := pki.EncodeCSR(template, key)
		if err != nil {
			s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error encoding certificate signing request: %v", err)
			return nil, err
		}

		csr, err := x509.ParseCertificateRequest(csrBytes)
		if err != nil {
			s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error parsing certificate signing request: %v", err)
			return nil, err
		}
		if err := csr.CheckSignature(); err != nil {
			s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error checking certificate signing request signature: %v", err)
			return nil, err
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
			s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error creating signing token: %v", err)
			return nil, err
		}

		var notAfter api.TimeDuration
		if crt.Spec.Duration != nil {
			notAfter.SetDuration(crt.Spec.Duration.Duration)
		}

		resp, err = s.provisioner.Sign(&api.SignRequest{
			CsrPEM: api.CertificateRequest{
				CertificateRequest: csr,
			},
			OTT:      token,
			NotAfter: notAfter,
		})
		if err != nil {
			s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error signing certificate: %v", err)
			return nil, err
		}
	} else {
		tlsCert := tls.Certificate{
			PrivateKey: key,
		}
		for _, c := range cert {
			tlsCert.Certificate = append(tlsCert.Certificate, c.Raw)
		}
		tr := getDefaultTransport(&tls.Config{
			Certificates:             []tls.Certificate{tlsCert},
			PreferServerCipherSuites: true,
			RootCAs:                  rootCA,
		})

		// Renew using an mTLS connection
		resp, err = s.provisioner.Renew(tr)
		if err != nil {
			s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error renewing certificate: %v", err)
			return nil, err
		}
	}

	// Encode server certificate with the intermediate
	certPem, err := pki.EncodeX509(resp.ServerPEM.Certificate)
	if err != nil {
		s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error encoding certificate: %v", err)
		return nil, err
	}
	chainPem, err := pki.EncodeX509(resp.CaPEM.Certificate)
	if err != nil {
		s.Recorder.Eventf(crt, corev1.EventTypeWarning, "ErrorSigning", "Error encoding intermediate certificate: %v", err)
		return nil, err
	}
	certPem = append(certPem, chainPem...)

	return &issuer.IssueResponse{
		PrivateKey:  keyPem,
		Certificate: certPem,
		CA:          caPem,
	}, nil
}

// getDefaultTransport returns an http.Transport with the same parameters than
// http.DefaultTransport.
func getDefaultTransport(tlsConfig *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}
}
