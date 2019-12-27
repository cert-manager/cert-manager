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

package request

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/apis/cert-managerctl/v1alpha1"
	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/client"
	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/util"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

type Request struct {
	client *client.Client
	opts   *v1alpha1.Request
}

func New(client *client.Client, opts *v1alpha1.Request) *Request {
	return &Request{
		client: client,
		opts:   opts,
	}
}

func (r *Request) csr(csrPEM []byte, opts *v1alpha1.Request) error {
	var duration *metav1.Duration

	if len(opts.CertificateRequestSpec.Duration) > 0 {
		d, err := time.ParseDuration(opts.CertificateRequestSpec.Duration)
		if err != nil {
			return err
		}
		duration = &metav1.Duration{
			Duration: d,
		}
	}

	durationTime := apiutil.DefaultCertDuration(duration)

	cr := &cmapi.CertificateRequest{
		ObjectMeta: util.DefaultGenerateObjectMeta(opts.ObjectMeta),
		Spec: cmapi.CertificateRequestSpec{
			CSRPEM: csrPEM,
			IsCA:   opts.CertificateRequestSpec.IsCA,
			Duration: &metav1.Duration{
				Duration: durationTime,
			},
			IssuerRef: cmmeta.ObjectReference{
				Name:  opts.IssuerRef.Name,
				Kind:  opts.IssuerRef.Kind,
				Group: opts.IssuerRef.Group,
			},
		},
	}

	log.Info("creating CertificateRequest")

	cr, err := r.client.CreateCertificateRequest(cr)
	if err != nil {
		return err
	}

	log.Infof("waiting for CertificateRequest %s/%s to become ready",
		cr.Namespace, cr.Name)
	cr, err = r.client.WaitForCertificateRequestReady(
		cr.Name, cr.Namespace, time.Second*30)
	if err != nil {
		return fmt.Errorf("failed waiting for resource %s/%s to become ready: %s",
			cr.Namespace, cr.Name, err)
	}

	log.Info("signed certificate successfully issued")

	if out := opts.CertificateRequestSpec.OutputFile; len(out) > 0 {
		log.Infof("writing signed certificate request to %s", out)

		if err := os.MkdirAll(filepath.Dir(out), 0744); err != nil {
			return err
		}

		return ioutil.WriteFile(out, cr.Status.Certificate, 0600)
	}

	fmt.Printf("%s", cr.Status.Certificate)

	return nil
}
