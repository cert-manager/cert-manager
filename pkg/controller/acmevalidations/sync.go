package certificates

import (
	"context"
	"fmt"
	"time"

	api "k8s.io/api/core/v1"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const renewBefore = time.Hour * 24 * 30

const (
	errorIssuerNotFound       = "ErrorIssuerNotFound"
	errorIssuerNotReady       = "ErrorIssuerNotReady"
	errorIssuerInit           = "ErrorIssuerInitialization"
	errorCheckCertificate     = "ErrorCheckCertificate"
	errorGetCertificate       = "ErrorGetCertificate"
	errorPreparingCertificate = "ErrorPrepareCertificate"
	errorIssuingCertificate   = "ErrorIssueCertificate"
	errorRenewingCertificate  = "ErrorRenewCertificate"
	errorSavingCertificate    = "ErrorSaveCertificate"

	reasonPreparingCertificate = "PrepareCertificate"
	reasonIssuingCertificate   = "IssueCertificate"
	reasonRenewingCertificate  = "RenewCertificate"

	successCeritificateIssued  = "CeritifcateIssued"
	successCeritificateRenewed = "CeritifcateRenewed"
	successRenewalScheduled    = "RenewalScheduled"

	messageIssuerNotFound            = "Issuer %s does not exist"
	messageIssuerNotReady            = "Issuer %s not ready"
	messageIssuerErrorInit           = "Error initializing issuer: "
	messageErrorCheckCertificate     = "Error checking existing TLS certificate: "
	messageErrorGetCertificate       = "Error getting TLS certificate: "
	messageErrorPreparingCertificate = "Error preparing issuer for certificate: "
	messageErrorIssuingCertificate   = "Error issuing certificate: "
	messageErrorRenewingCertificate  = "Error renewing certificate: "
	messageErrorSavingCertificate    = "Error saving TLS certificate: "

	messagePreparingCertificate = "Preparing certificate with issuer"
	messageIssuingCertificate   = "Issuing certificate..."
	messageRenewingCertificate  = "Renewing certificate..."

	messageCertificateIssued  = "Certificated issued successfully"
	messageCertificateRenewed = "Certificated renewed successfully"
	messageRenewalScheduled   = "Certificate scheduled for renewal in %d hours"
)

func (c *Controller) Sync(ctx context.Context, val *v1alpha1.ACMEValidation) (err error) {
	// step zero: check if the referenced issuer exists and is ready
	issuerObj, err := c.getGenericIssuer(val.Spec.IssuerRef, val.Namespace)

	if err != nil {
		s := fmt.Sprintf(messageIssuerNotFound, err.Error())
		glog.Info(s)
		c.recorder.Event(val, api.EventTypeWarning, errorIssuerNotFound, s)
		return err
	}

	issuerReady := issuerObj.HasCondition(v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	})
	if !issuerReady {
		s := fmt.Sprintf(messageIssuerNotReady, issuerObj.GetObjectMeta().Name)
		glog.Info(s)
		c.recorder.Event(val, api.EventTypeWarning, errorIssuerNotReady, s)
		return fmt.Errorf(s)
	}

	i, err := c.issuerFactory.IssuerFor(issuerObj)
	if err != nil {
		s := messageIssuerErrorInit + err.Error()
		glog.Info(s)
		c.recorder.Event(val, api.EventTypeWarning, errorIssuerInit, s)
		return err
	}

	return nil
}

func (c *Controller) getGenericIssuer(ref v1alpha1.ObjectReference, ns string) (v1alpha1.GenericIssuer, error) {
	switch ref.Kind {
	case "", v1alpha1.IssuerKind:
		return c.issuerLister.Issuers(ns).Get(ref.Name)
	case v1alpha1.ClusterIssuerKind:
		if c.clusterIssuerLister == nil {
			return nil, fmt.Errorf("cannot get ClusterIssuer %s as cert-manager is scoped to a single namespace", ref.Name)
		}
		return c.clusterIssuerLister.Get(ref.Name)
	default:
		return nil, fmt.Errorf(`invalid value %q for issuer kind. Must be empty, %q or %q`, ref.Kind, v1alpha1.IssuerKind, v1alpha1.ClusterIssuerKind)
	}
}
