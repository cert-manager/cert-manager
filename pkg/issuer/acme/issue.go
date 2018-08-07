package acme

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

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
	commonName := pki.CommonNameForCertificate(crt)
	altNames := pki.DNSNamesForCertificate(crt)

	cl, err := a.helper.ClientForIssuer(a.issuer)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueError, fmt.Sprintf("Failed to get ACME client: %v", err), false)
		return nil, nil, fmt.Errorf("error creating ACME client: %s", err.Error())
	}

	orderURL := crt.Status.ACMEStatus().Order.URL
	if orderURL == "" {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorInvalidConfig, "status.acme.order.url must be set", false)
		return nil, nil, fmt.Errorf("certificate order url cannot be blank")
	}

	order, err := cl.GetOrder(ctx, orderURL)
	if err != nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueError, fmt.Sprintf("Failed to get order details: %v", err), false)
		return nil, nil, fmt.Errorf("error getting order details: %v", err)
	}

	if order.Status != acmeapi.StatusReady {
		err := fmt.Errorf("expected certificate status to be %q, but it is %q", acmeapi.StatusReady, order.Status)
		// print a more helpful message to users when an order is marked 'valid'.
		// this happens when all challenges have been completed successfully, but
		// the acme server has not finished processing the order.
		if order.Status == acmeapi.StatusValid {
			err = fmt.Errorf("%v. Waiting until Order transitions into %q state", err, acmeapi.StatusReady)
		}
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorIssueError, err.Error(), false)
		return nil, nil, err
	}

	// get existing certificate private key
	key, err := kube.SecretTLSKey(a.secretsLister, crt.Namespace, crt.Spec.SecretName)
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
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
	certSlice, err := cl.FinalizeOrder(ctx, order.FinalizeURL, derBytes)
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
		a.recorder.Eventf(crt, corev1.EventTypeWarning, errorIssueError, "Failed to finalize order: %v", err)
		return nil, nil, fmt.Errorf("error getting certificate from acme server: %s", err)
	}

	// encode the retrieved certificate
	certBuffer := bytes.NewBuffer([]byte{})
	for _, cert := range certSlice {
		pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	}

	a.recorder.Eventf(crt, corev1.EventTypeNormal, successCertObtained, "Obtained certificate from ACME server")

	glog.Infof("successfully obtained certificate: cn=%q altNames=%+v url=%q", commonName, altNames, orderURL)
	// encode the private key and return
	keyPem, err := pki.EncodePrivateKey(key)
	if err != nil {
		s := messageErrorEncodePrivateKey + err.Error()
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorEncodePrivateKey, s, false)
		return nil, nil, err
	}

	return keyPem, certBuffer.Bytes(), nil
}

func (a *Acme) Issue(ctx context.Context, crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	key, cert, err := a.obtainCertificate(ctx, crt)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, err
}
