package acme

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/acme"
	"k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/golang/glog"
	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/util/kube"
	"github.com/jetstack-experimental/cert-manager/pkg/util/pki"
)

const (
	errorAccountRegistrationFailed = "ErrorRegisteringACMEAccount"
	errorAccountVerificationFailed = "ErrorVerifyingACMEAccount"

	successAccountRegistered = "ACMEAccountRegistered"
	successAccountVerified   = "ACMEAccountVerified"

	messageAccountRegistrationFailed = "Failed to register ACME account: "
	messageAccountVerificationFailed = "Failed to verify ACME account: "
	messageAccountRegistered         = "The ACME account was registered with the ACME server"
	messageAccountVerified           = "The ACME account was verified with the ACME server"
)

func (a *Acme) Setup() (v1alpha1.IssuerStatus, error) {
	update := a.issuer.DeepCopy()

	_, accountPrivKey, err := kube.GetKeyPair(a.client, a.issuer.Namespace, a.issuer.Spec.ACME.PrivateKey)

	if k8sErrors.IsNotFound(err) {
		accountPrivKey, err = pki.GenerateRSAPrivateKey(2048)

		if err != nil {
			s := messageAccountRegistrationFailed + "error generating private key " + err.Error()
			glog.Info(s)
			a.recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountRegistrationFailed, s)
			v1alpha1.UpdateIssuerStatusCondition(update, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)
			return update.Status, fmt.Errorf(s)
		}

		_, err = kube.EnsureSecret(a.client, &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      a.issuer.Spec.ACME.PrivateKey,
				Namespace: a.issuer.Namespace,
			},
			Data: map[string][]byte{
				v1.TLSPrivateKeyKey: pki.EncodePKCS1PrivateKey(accountPrivKey),
			},
		})

		if err != nil {
			s := messageAccountRegistrationFailed + "error saving private key " + err.Error()
			glog.Info(s)
			a.recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountRegistrationFailed, s)
			v1alpha1.UpdateIssuerStatusCondition(update, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)
			return update.Status, fmt.Errorf(s)
		}
	}

	if accountPrivKey == nil {
		s := messageAccountRegistrationFailed + err.Error()
		glog.Info(s)
		a.recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountRegistrationFailed, s)
		v1alpha1.UpdateIssuerStatusCondition(update, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)
		return update.Status, fmt.Errorf(s)
	}

	cl := acme.Client{
		Key:          accountPrivKey,
		DirectoryURL: a.issuer.Spec.ACME.Server,
	}

	_, err = cl.GetReg(context.Background(), a.issuer.Status.ACME.URI)

	if err == nil {
		glog.Info(messageAccountVerified)
		a.recorder.Event(a.issuer, v1.EventTypeNormal, successAccountVerified, messageAccountVerified)
		v1alpha1.UpdateIssuerStatusCondition(update, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successAccountVerified, messageAccountVerified)
		return update.Status, nil
	}

	s := messageAccountVerificationFailed + err.Error()
	glog.Info(s)
	a.recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountVerificationFailed, s)

	acc := &acme.Account{
		Contact: []string{fmt.Sprintf("mailto:%s", strings.ToLower(a.issuer.Spec.ACME.Email))},
	}

	// todo (@munnerz): don't use ctx.Background() here
	account, err := cl.Register(context.Background(), acc, acme.AcceptTOS)

	if err != nil {
		s := messageAccountRegistrationFailed + err.Error()
		glog.Info(s)
		a.recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountRegistrationFailed, s)
		v1alpha1.UpdateIssuerStatusCondition(update, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)
		return update.Status, err
	}

	glog.V(4).Info(messageAccountRegistered)
	a.recorder.Event(a.issuer, v1.EventTypeNormal, successAccountRegistered, messageAccountRegistered)
	v1alpha1.UpdateIssuerStatusCondition(update, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successAccountRegistered, messageAccountRegistered)
	update.Status.ACMEStatus().URI = account.URI

	return update.Status, nil
}
