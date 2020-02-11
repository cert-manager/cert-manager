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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

type ECDSA struct{}

var _ Codec = ECDSA{}

func (c ECDSA) Encode(d Bundle) (*RawData, error) {
	data := map[string][]byte{}
	ecPK, ok := d.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an ECDSA key")
	}
	pkDER, err := x509.MarshalECPrivateKey(ecPK)
	if err != nil {
		return nil, err
	}
	pkPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: pkDER,
	})
	if pkPEM == nil {
		return nil, errors.NewInvalidData("failed to encode ECDSA private key to PEM format")
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

func (c ECDSA) Decode(e RawData) (*Bundle, error) {
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
		// "EC PRIVATE KEY" is the PEM marker used for ECDSA encoded data
		if block.Type != "EC PRIVATE KEY" {
			return d, errors.NewInvalidData("unexpected PEM block type %q - ECDSA data should specify the type as 'EC PRIVATE KEY'", block.Type)
		}
		pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return d, errors.NewInvalidData("failed to decode private key: %v", err)
		}
		d.PrivateKey = pk
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
