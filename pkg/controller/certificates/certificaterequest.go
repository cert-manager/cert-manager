package certificates

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	certNameLabelKey = "acme.cert-manager.io/order-name"
)

// return an error on failure. If retrieval is succesful, the certificate data
// and private key will be stored in the named secret
func (c *Controller) issue(ctx context.Context, issuer v1alpha1.GenericIssuer, key crypto.Signer, crt *v1alpha1.Certificate) error {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	csr, err := pki.GenerateCSR(issuer, crt)
	if err != nil {
		return err
	}

	if key == nil {
		log.Info("generating new private key")
		key, err = c.generateNewPrivateKey(ctx, crt)
		if err != nil {
			return err
		}
	}

	csrPEM, err := pki.EncodeCSR(csr, key)
	if err != nil {
		return err
	}

	crs, err := c.listCertificateRequestsForCertificate(crt)
	if err != nil {
		return err
	}

	// create CertificateRequest
	if len(crs) == 0 {
		// return here and wait till next sync to catch CertificateRequest update
		return c.createCertificateRequest(crt, csrPEM)
	}

	// Loop through CertificateRequests and if any don't match our current
	// Certificate, delete
	var delErrs []error
	for i := 0; i < len(crs); i++ {

		matches, matchErrs := c.certificateRequestMatchesCertificateSpec(crt, csrPEM, crs[i])
		if !matches {

			dbg.Info(fmt.Sprintf("certificate request spec does not match certificate, deleting %s/%s",
				crs[i].Namespace, crs[i].Name), "diff", strings.Join(matchErrs, ", "))

			err = c.deleteCertificateRequests(crs[i])
			if err != nil {
				delErrs = append(delErrs, err)
			}

			crs = append(crs[:i], crs[i+1:]...)
			i -= 1
		}
	}

	if len(delErrs) > 0 {
		return utilerrors.NewAggregate(delErrs)
	}

	// no CertificateRequests left
	if len(crs) == 0 {
		return c.createCertificateRequest(crt, csrPEM)
	}

	// We loop through all CertificateRequests to find one that's ready.
	// If we don't find one then we back off.
	// If we do find one that's valid, get the cert and delete.
	for _, cr := range crs {
		ready := apiutil.CertificateRequestHasCondition(cr, v1alpha1.CertificateRequestCondition{
			Type:   v1alpha1.CertificateRequestConditionReady,
			Status: v1alpha1.ConditionTrue,
		})

		if !ready {
			continue
		}

		keyPem, err := pki.EncodePrivateKey(key)
		if err != nil {
			return err
		}

		if _, err := c.updateSecret(ctx, crt, crt.Namespace, cr.Status.Certificate, keyPem, cr.Status.CA); err != nil {
			s := messageErrorSavingCertificate + err.Error()
			log.Error(err, "error saving certificate")
			c.Recorder.Event(crt, corev1.EventTypeWarning, errorSavingCertificate, s)
			return err
		}

		certx509, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
		if err != nil {
			return err
		}

		c.setCertificateStatus(crt, key, certx509)

		c.Recorder.Event(crt, corev1.EventTypeNormal, successCertificateIssued, "Certificate issued successfully")
		// as we have just written a certificate, we should schedule it for renewal
		c.scheduleRenewal(ctx, crt)

		return c.deleteCertificateRequests(crs...)
	}

	// No CertificateRequests are ready yet so we wait till the next sync

	return nil
}

func (c *Controller) deleteCertificateRequests(crs ...*v1alpha1.CertificateRequest) error {
	var errs []error

	for _, cr := range crs {
		err := c.CMClient.CertmanagerV1alpha1().CertificateRequests(cr.Namespace).
			Delete(cr.Name, nil)

		if err != nil {
			errs = append(errs, fmt.Errorf("failed to delete certificate request %s/%s",
				cr.Namespace, cr.Name))
		}
	}

	return utilerrors.NewAggregate(errs)
}

func (c *Controller) createCertificateRequest(crt *v1alpha1.Certificate, csrPEM []byte) error {
	_, err := c.CMClient.CertmanagerV1alpha1().CertificateRequests(crt.Namespace).Create(
		buildCertificateRequest(csrPEM, crt))
	if err != nil {
		return err
	}

	return nil
}

func (c *Controller) certificateRequestMatchesCertificateSpec(cert *v1alpha1.Certificate, csrPEM []byte, cr *v1alpha1.CertificateRequest) (bool, []string) {
	var errs []string

	if cert == nil || cr == nil {
		errs = append(errs, "certificate or certificate request nil")
		return false, errs
	}

	if cert.Spec.IsCA != cr.Spec.IsCA {
		errs = append(errs, "certificate IsCA does not match certificate request")
	}

	if cert.Spec.Duration != nil {
		if cr.Spec.Duration == nil ||
			cert.Spec.Duration.String() != cr.Spec.Duration.String() {
			errs = append(errs, "certificate duration does not match certificate request duration")
		}
	} else if cr.Spec.Duration != nil {
		errs = append(errs, "certificate duration not defined in certificate but is in certificate request")
	}

	if cert.Spec.IssuerRef != cr.Spec.IssuerRef {
		errs = append(errs, "certificate issuer reference does not match certificate request")
	}

	if csrPEM == nil || !bytes.Equal(csrPEM, cr.Spec.CSRPEM) {
		errs = append(errs, "certificate request CSR PEM does not match that generated by certificate")
	}

	return len(errs) == 0, errs
}

func buildCertificateRequest(csr []byte, crt *v1alpha1.Certificate) *v1alpha1.CertificateRequest {
	return &v1alpha1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: crt.Name,
			Namespace:    crt.Namespace,
		},
		Spec: v1alpha1.CertificateRequestSpec{
			CSRPEM:    csr,
			Duration:  crt.Spec.Duration.DeepCopy(),
			IsCA:      crt.Spec.IsCA,
			IssuerRef: crt.Spec.IssuerRef,
		},
	}
}

func (c *Controller) listCertificateRequestsForCertificate(crt *v1alpha1.Certificate) ([]*v1alpha1.CertificateRequest, error) {
	// create a selector that we can use to find all existing CertificateRequests for the Certificate
	sel, err := certificateRequestSelectorForCertificate(crt)
	if err != nil {
		return nil, err
	}

	// get the list of exising certificate requests for this certificate
	return c.certificateRequestLister.CertificateRequests(crt.Namespace).List(sel)
}

// challengeSelectorForCertificateRequest will construct a labels.Selector that
// can be used to find CertificateRequests associated with the given
// Certificate.
func certificateRequestSelectorForCertificate(c *v1alpha1.Certificate) (labels.Selector, error) {
	lbls := certificateRequestLabelsForCertificate(c)
	var reqs []labels.Requirement
	for k, v := range lbls {
		req, err := labels.NewRequirement(k, selection.Equals, []string{v})
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, *req)
	}
	return labels.NewSelector().Add(reqs...), nil
}

func certificateRequestLabelsForCertificate(c *v1alpha1.Certificate) map[string]string {
	return map[string]string{
		certNameLabelKey: c.Name,
	}
}
