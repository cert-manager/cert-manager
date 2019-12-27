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

package update

import (
	"fmt"
	"io/ioutil"

	log "github.com/sirupsen/logrus"

	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/apis/cert-managerctl/v1alpha1"
	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/client"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

type Update struct {
	client *client.Client
	opts   *v1alpha1.Update
}

func New(client *client.Client, opts *v1alpha1.Update) *Update {
	return &Update{
		client: client,
		opts:   opts,
	}
}

func (u *Update) CertificateRequest() error {
	var err error
	var certPEM, caPEM []byte

	if len(u.opts.CertificatePEM) > 0 {
		certPEM, err = u.readCertFile(u.opts.CertificatePEM)
		if err != nil {
			return err
		}

		log.Infof("Using Certificate PEM at %q", u.opts.CertificatePEM)
	}

	if len(u.opts.CAPEM) > 0 {
		caPEM, err = u.readCertFile(u.opts.CAPEM)
		if err != nil {
			return err
		}

		log.Infof("Using CA PEM at %q", u.opts.CertificatePEM)
	}

	switch u.opts.ReadyConditionReason {
	case cmapi.CertificateRequestReasonPending, cmapi.CertificateRequestReasonFailed,
		cmapi.CertificateRequestReasonIssued:
		break

	default:
		return fmt.Errorf(
			`expecting --ready-condition-reason to contain one value of %q, %q or %q, got: %q`,
			cmapi.CertificateRequestReasonPending, cmapi.CertificateRequestReasonFailed,
			cmapi.CertificateRequestReasonIssued, u.opts.ReadyConditionReason)
	}

	cr, err := u.client.CertificateRequest(u.opts.Namespace, u.opts.Name)
	if err != nil {
		return err
	}

	cr.Status.Certificate = certPEM
	cr.Status.CA = caPEM

	condition := cmmeta.ConditionFalse
	if u.opts.ReadyConditionReason == cmapi.CertificateRequestReasonIssued {
		condition = cmmeta.ConditionTrue
	}

	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, condition, u.opts.ReadyConditionReason, u.opts.ReadyConditionMessage)

	_, err = u.client.UpdateCertificateRequest(cr)
	if err != nil {
		return err
	}

	log.Infof("Updated CertificateRequest %s/%s with condition %q: %s",
		cr.Name, cr.Namespace, u.opts.ReadyConditionReason, u.opts.ReadyConditionMessage)

	return nil
}

func (u *Update) readCertFile(path string) ([]byte, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	_, err = pki.DecodeX509CertificateChainBytes(b)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate file %q: %s",
			path, err)
	}

	return b, nil
}

//func (g *Get) Cert() error {
//	opts := g.opts.Certificate
//
//	cr, err := g.getOrWait(g.opts.Namespace, g.opts.Name, opts.Wait)
//	if err != nil {
//		return err
//	}
//
//	if apiutil.CertificateRequestReadyReason(cr) != cmapi.CertificateRequestReasonIssued {
//		return fmt.Errorf("certificate request %s/%s not ready: %s: %s",
//			cr.Name, cr.Namespace, cr.Status.Conditions)
//	}
//
//	if out := opts.OutputFile; len(out) > 0 {
//		if err := os.MkdirAll(filepath.Dir(out), 0744); err != nil {
//			return err
//		}
//
//		return ioutil.WriteFile(out, cr.Status.Certificate, 0600)
//	}
//
//	fmt.Printf("%s", cr.Status.Certificate)
//
//	return nil
//}
//
//func (g *Get) getOrWait(ns, name string, wait bool) (*cmapi.CertificateRequest, error) {
//	if !wait {
//		return g.client.CertificateRequest(ns, name)
//	}
//
//	return g.client.WaitForCertificateRequestReady(ns, name, time.Second*30)
//}
