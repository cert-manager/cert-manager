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

package get

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/apis/cert-managerctl/v1alpha1"
	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/client"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
)

type Get struct {
	client *client.Client
	opts   *v1alpha1.Get
}

func New(client *client.Client, opts *v1alpha1.Get) *Get {
	return &Get{
		client: client,
		opts:   opts,
	}
}

func (g *Get) Cert() error {
	opts := g.opts.Certificate

	cr, err := g.getOrWait(g.opts.Namespace, g.opts.Name, opts.Wait)
	if err != nil {
		return err
	}

	if apiutil.CertificateRequestReadyReason(cr) != cmapi.CertificateRequestReasonIssued {
		return fmt.Errorf("certificate request %s/%s not ready: %s: %s",
			cr.Name, cr.Namespace, cr.Status.Conditions)
	}

	if out := opts.OutputFile; len(out) > 0 {
		if err := os.MkdirAll(filepath.Dir(out), 0744); err != nil {
			return err
		}

		return ioutil.WriteFile(out, cr.Status.Certificate, 0600)
	}

	fmt.Printf("%s", cr.Status.Certificate)

	return nil
}

func (g *Get) getOrWait(ns, name string, wait bool) (*cmapi.CertificateRequest, error) {
	if !wait {
		return g.client.CertificateRequest(ns, name)
	}

	return g.client.WaitForCertificateRequestReady(ns, name, time.Second*30)
}
