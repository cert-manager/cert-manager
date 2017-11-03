package acme

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang/glog"
	"golang.org/x/crypto/acme"
	"k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorAccountRegistrationFailed = "ErrRegisterACMEAccount"
	errorAccountVerificationFailed = "ErrVerifyACMEAccount"

	successAccountRegistered = "ACMEAccountRegistered"
	successAccountVerified   = "ACMEAccountVerified"

	messageAccountRegistrationFailed = "Failed to register ACME account: "
	messageAccountVerificationFailed = "Failed to verify ACME account: "
	messageAccountRegistered         = "The ACME account was registered with the ACME server"
	messageAccountVerified           = "The ACME account was verified with the ACME server"
)

// Setup will verify an existing ACME registration, or create one if not
// already registered.
func (a *Acme) Setup(ctx context.Context) error {
	cl, err := a.acmeClient()
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		glog.V(4).Infof("%s: generating acme account private key %q", a.issuer.GetObjectMeta().Name, a.issuer.GetSpec().ACME.PrivateKey.Name)
		accountPrivKey, err := a.createAccountPrivateKey()
		if err != nil {
			s := messageAccountRegistrationFailed + err.Error()
			a.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)
			return fmt.Errorf(s)
		}
		a.issuer.GetStatus().ACMEStatus().URI = ""
		cl = &acme.Client{
			Key:          accountPrivKey,
			DirectoryURL: a.issuer.GetSpec().ACME.Server,
		}
	} else if err != nil {
		s := messageAccountVerificationFailed + err.Error()
		glog.V(4).Infof("%s: %s", a.issuer.GetObjectMeta().Name, s)
		a.recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountVerificationFailed, s)
		return err
	}

	account, err := a.registerAccount(ctx, cl)
	if err != nil {
		s := messageAccountVerificationFailed + err.Error()
		glog.V(4).Infof("%s: %s", a.issuer.GetObjectMeta().Name, s)
		a.recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountVerificationFailed, s)
		a.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)
		return err
	}

	glog.V(4).Infof("%s: verified existing registration with ACME server", a.issuer.GetObjectMeta().Name)
	a.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successAccountRegistered, messageAccountRegistered)
	a.issuer.GetStatus().ACMEStatus().URI = account.URI

	return nil
}

// registerAccount will register a new ACME account with the server. If an
// account with the clients private key already exists, it will attempt to look
// up and verify the corresponding account, and will return that. If this fails
// it will return the
func (a *Acme) registerAccount(ctx context.Context, cl *acme.Client) (*acme.Account, error) {
	acc := &acme.Account{
		Contact: []string{fmt.Sprintf("mailto:%s", strings.ToLower(a.issuer.GetSpec().ACME.Email))},
	}
	acc, err := cl.Register(ctx, acc, acme.AcceptTOS)
	if err != nil {
		typedErr, ok := err.(*acme.Error)
		// if this isn't an ACME error, we should just return it
		if !ok {
			return nil, err
		}
		if typedErr.StatusCode == http.StatusConflict {
			accountUri := typedErr.Header.Get("Location")
			if accountUri == "" {
				return nil, fmt.Errorf("unexpected error - 409 Conflict error returned, but no Location header set: %s", typedErr.Error())
			}
			return a.verifyAccount(ctx, cl, accountUri)
		}
	}
	return acc, nil
}

// verifyAccount will verify an ACME account with the given URI.
func (a *Acme) verifyAccount(ctx context.Context, cl *acme.Client, uri string) (*acme.Account, error) {
	acc, err := cl.GetReg(ctx, uri)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func (a *Acme) createAccountPrivateKey() (*rsa.PrivateKey, error) {
	secretName, secretKey := a.acmeAccountPrivateKeyMeta()
	accountPrivKey, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		return nil, err
	}

	_, err = kube.EnsureSecret(a.client, &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: a.issuerResourcesNamespace,
		},
		Data: map[string][]byte{
			secretKey: pki.EncodePKCS1PrivateKey(accountPrivKey),
		},
	})

	if err != nil {
		return nil, err
	}

	return accountPrivKey, err
}
