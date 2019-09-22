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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/apis/cert-managerctl/v1alpha1"
	cmctlutil "github.com/jetstack/cert-manager/cmd/cert-managerctl/app/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func (r Request) Cert() error {
	opts := r.opts.Certificate

	uris, err := cmctlutil.ParseURLs(opts.URISANs)
	if err != nil {
		return err
	}

	keyBundle, err := privateKey(opts.Key)
	if err != nil {
		return err
	}

	commonName, err := commonName(opts)
	if err != nil {
		return err
	}

	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: opts.Organizations,
		},
		DNSNames:           opts.DNSNames,
		IPAddresses:        cmctlutil.ParseIPAddresses(opts.IPAddresses),
		URIs:               uris,
		PublicKey:          keyBundle.PrivateKey.Public(),
		PublicKeyAlgorithm: keyBundle.PublicKeyAlgorithm,
		SignatureAlgorithm: keyBundle.SignatureAlgorithm,
	}

	csrPEM, err := pki.EncodeCSR(csr, keyBundle.PrivateKey)
	if err != nil {
		return err
	}

	return r.csr(csrPEM, &v1alpha1.Request{
		IssuerRef:   r.opts.IssuerRef,
		Certificate: opts,
		ObjectMeta:  r.opts.ObjectMeta,
	})
}

func privateKey(keyPath string) (*v1alpha1.KeyBundle, error) {
	exists, err := cmctlutil.FileExists(keyPath)
	if err != nil {
		return nil, err
	}

	var keyBundle *v1alpha1.KeyBundle
	if !exists {
		sk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		keyPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(sk),
			},
		)

		if err := os.MkdirAll(filepath.Dir(keyPath), 0744); err != nil {
			return nil, err
		}

		if err := ioutil.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return nil, err
		}

		return &v1alpha1.KeyBundle{
			PrivateKey:         sk,
			SignatureAlgorithm: x509.SHA256WithRSA,
			PublicKeyAlgorithm: x509.RSA,
		}, nil
	}

	keyBundle, err = cmctlutil.ParsePrivateKeyFile(keyPath)
	if err != nil {
		return nil, err
	}

	return keyBundle, nil
}

func (r *Request) Sign() error {
	opts := r.opts.Sign

	if len(opts.CSRPEM) == 0 {
		return errors.New("csr path file location is empty")
	}

	csrPEM, err := ioutil.ReadFile(opts.CSRPEM)
	if err != nil {
		return err
	}

	return r.csr(csrPEM, &v1alpha1.Request{
		IssuerRef:              r.opts.IssuerRef,
		CertificateRequestSpec: r.opts.CertificateRequestSpec,
		ObjectMeta:             r.opts.ObjectMeta,
	})
}

func commonName(opts *v1alpha1.RequestCertificate) (string, error) {
	if len(opts.CommonName) > 0 {
		return opts.CommonName, nil
	}

	if len(opts.DNSNames) == 0 {
		return "", errors.New("no common name or DNS names given")
	}

	return opts.DNSNames[0], nil
}
