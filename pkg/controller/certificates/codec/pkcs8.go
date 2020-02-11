/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package codec

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

// PKCS8 knows how to encode and decode RSA PKCS.8 formatted private key
// certificate data.
type PKCS8 struct{}

var _ Codec = PKCS8{}

// Encode encodes the given private key into PEM-encoded PKCS.1 format.
// The certificate be encoded into DER format and stored as a PEM,
func (p PKCS8) Encode(d Bundle) (*RawData, error) {
	data := map[string][]byte{}
	pkDER, err := x509.MarshalPKCS8PrivateKey(d.PrivateKey)
	if err != nil {
		return nil, err
	}
	pkPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkDER,
	})
	if pkPEM == nil {
		return nil, fmt.Errorf("failed to encode private key to PEM format")
	}
	data[corev1.TLSPrivateKeyKey] = pkPEM

	if len(d.Certificates) > 0 {
		certsPEM, err := encodeCertificatesASN1PEM(d.Certificates)
		if err != nil {
			return nil, err
		}
		data[corev1.TLSCertKey] = certsPEM
	}

	if len(d.CA) > 0 {
		caPEM, err := encodeCertificatesASN1PEM(d.CA)
		if err != nil {
			return nil, err
		}
		data[cmmeta.TLSCAKey] = caPEM
	}

	return &RawData{Data: data}, nil
}

func (p PKCS8) Decode(e RawData) (*Bundle, error) {
	d := &Bundle{}
	pkPEM := e.Data[corev1.TLSPrivateKeyKey]
	certsPEM := e.Data[corev1.TLSCertKey]
	caPEM := e.Data[cmmeta.TLSCAKey]
	var err error
	if len(pkPEM) > 0 {
		// decode the private key pem
		block, _ := pem.Decode(pkPEM)
		if block == nil {
			return d, errors.NewInvalidData("failed to decode PEM block")
		}
		// "PRIVATE KEY" is the PEM marker used for PKCS8 encoded data
		if block.Type != "PRIVATE KEY" {
			return d, errors.NewInvalidData("unexpected PEM block type %q - PKCS8 data should specify the type as 'PRIVATE KEY'", block.Type)
		}
		pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return d, fmt.Errorf("failed to decode private key: %v", err)
		}
		signer, ok := pk.(crypto.Signer)
		if !ok {
			return d, errors.NewInvalidData("stored private key does not implement crypto.Signer")
		}
		d.PrivateKey = signer
	}
	if len(certsPEM) > 0 {
		d.Certificates, err = pki.DecodeX509CertificateChainBytes(certsPEM)
		if err != nil {
			return d, errors.NewInvalidData(err.Error())
		}
	}
	if len(caPEM) > 0 {
		d.CA, err = pki.DecodeX509CertificateChainBytes(caPEM)
		if err != nil {
			return d, errors.NewInvalidData(err.Error())
		}
	}
	return d, nil
}
