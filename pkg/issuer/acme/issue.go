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

package acme

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

const (
	errorIssueError       = "IssueError"
	errorEncodePrivateKey = "ErrEncodePrivateKey"

	successCertObtained = "CertObtained"

	messageErrorEncodePrivateKey = "Error encoding private key: "
)

func (a *Acme) obtainCertificate(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	if crt.Status.ACMEStatus().OrderRef == nil || crt.Status.ACMEStatus().OrderRef.Name == "" {
		return nil, nil, fmt.Errorf("status.acme.orderRef.name must be set")
	}

	orderName := crt.Status.ACMEStatus().OrderRef.Name
	order, err := a.orderLister.Orders(crt.Namespace).Get(orderName)
	if err != nil {
		// we return err without checking for IsNotFound because Prepare already
		// performs cleanup in the event the referenced Order does not exist.
		// this saves us re-implementing missing order handling here.
		return nil, nil, err
	}

	// TODO: ensure the names on the Order match the desired names for this Certificate
	// If not, we should return an error here in order to trigger the hash-detection
	// logic in Prepare to run.

	cl, err := a.helper.ClientForIssuer(a.issuer)
	if err != nil {
		return nil, nil, err
	}

	commonName := pki.CommonNameForCertificate(crt)
	altNames := pki.DNSNamesForCertificate(crt)

	// get existing certificate private key
	key, err := kube.SecretTLSKey(a.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if apierrors.IsNotFound(err) || errors.IsInvalidData(err) {
		key, err = pki.GeneratePrivateKeyForCertificate(crt)
		if err != nil {
			crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueError, fmt.Sprintf("Failed to generate certificate private key: %v", err), false)
			return nil, nil, fmt.Errorf("error generating private key: %s", err.Error())
		}
	}
	if err != nil {
		// don't log these errors to the api as they are likely transient
		return nil, nil, fmt.Errorf("error getting certificate private key: %s", err.Error())
	}

	var certSlice [][]byte
	// StatusReady indicates that the order is ready to be finalized.
	// Once the order has been finalized, it will transition into the 'valid'
	// state.
	// The only way to obtain a certificate from an already 'valid' order is to
	// call the orders GetCertificate function.
	// You can see we do this below *iff* certSlice is nil.
	if order.Status == acmeapi.StatusReady {
		// generate a csr
		template, err := pki.GenerateCSR(a.issuer, crt)
		if err != nil {
			// TODO: this should probably be classed as a permanant failure
			return nil, nil, err
		}

		derBytes, err := pki.EncodeCSR(template, key)
		if err != nil {
			crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueError, fmt.Sprintf("Failed to generate certificate request: %v", err), false)
			return nil, nil, err
		}

		// obtain a certificate from the acme server
		certSlice, err = cl.FinalizeOrder(ctx, order.FinalizeURL, derBytes)
		if err != nil {
			// this handles an edge case where a certificate ends out with an order
			// that is in an invalid state.
			// ideally we would instead call GetCertificate on the ACME client
			// instead of FinalizeOrder, which would save us creating a new order
			// just to issue a new certificate.
			// The underlying ACME client doesn't expose this though yet.
			if acmeErr, ok := err.(*acmeapi.Error); ok {
				if acmeErr.StatusCode >= 400 && acmeErr.StatusCode <= 499 {
					crt.Status.ACMEStatus().Order.URL = ""
				}
			}
			// TODO: should we also set the FailedValidation status
			// condition here so back off can be applied?
			crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueError, fmt.Sprintf("Failed to finalize order: %v", err), false)
			a.Recorder.Eventf(crt, corev1.EventTypeWarning, errorIssueError, "Failed to finalize order: %v", err)
			return nil, nil, fmt.Errorf("error getting certificate from acme server: %s", err)
		}

	}

	// if the Certificate was marked 'valid', we need to retrieve the certificate
	// from the URL specified on the Order resource.
	if certSlice == nil {
		certSlice, err = cl.GetCertificate(ctx, order.CertificateURL)
		if err != nil {
			crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueError, fmt.Sprintf("Failed to retrieve certificate: %v", err), false)
			return nil, nil, fmt.Errorf("error retrieving certificate: %v", err)
		}
	}

	if len(certSlice) == 0 {
		return nil, nil, fmt.Errorf("invalid certificate returned from acme server")
	}

	x509Cert, err := x509.ParseCertificate(certSlice[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse returned x509 certificate: %v", err.Error())
	}

	// obtain a certificate from the acme server
	certSlice, err := cl.FinalizeOrder(ctx, order.Status.FinalizeURL, derBytes)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueError, fmt.Sprintf("Failed to finalize order: %v", err), false)
		a.Recorder.Eventf(crt, corev1.EventTypeWarning, errorIssueError, "Failed to finalize order: %v", err)
		return nil, nil, fmt.Errorf("error getting certificate from acme server: %s", err)
	}

	// encode the retrieved certificate
	certBuffer := bytes.NewBuffer([]byte{})
	for _, cert := range certSlice {
		pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	}

	a.Recorder.Eventf(crt, corev1.EventTypeNormal, successCertObtained, "Obtained certificate from ACME server")

	glog.Infof("successfully obtained certificate: cn=%q altNames=%+v url=%q", commonName, altNames, order.Status.URL)
	// encode the private key and return
	keyPem, err := pki.EncodePrivateKey(key)
	if err != nil {
		s := messageErrorEncodePrivateKey + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorEncodePrivateKey, s, false)
		return nil, nil, err
	}

	return keyPem, certBuffer.Bytes(), nil
}

func (a *Acme) Issue(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, []byte, error) {
	key, cert, err := a.obtainCertificate(ctx, crt)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, cert, nil, err
}
