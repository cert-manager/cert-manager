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
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// RawData contains encoded private key and certificate data.
type RawData struct {
	Data map[string][]byte
}

type Bundle struct {
	PrivateKey   crypto.Signer
	Certificates []*x509.Certificate
	CA           []*x509.Certificate
}

type Codec interface {
	Encoder
	Decoder
}

type Encoder interface {
	Encode(Bundle) (*RawData, error)
}

type Decoder interface {
	Decode(RawData) (*Bundle, error)
}

type Format int

const (
	PKCS1Format Format = iota
	ECDSAFormat
	PKCS8Format
)

type Options struct {
	Format Format
}

type Option func(opts *Options)

func SetFormat(format Format) Option {
	return func(opts *Options) {
		opts.Format = format
	}
}

func NewCodec(opts Options) (Codec, error) {
	switch opts.Format {
	case ECDSAFormat:
		return &ECDSA{}, nil
	case PKCS1Format:
		return &PKCS1{}, nil
	case PKCS8Format:
		return &PKCS8{}, nil
	}
	return nil, fmt.Errorf("unrecognised format %v", opts.Format)
}

func encodeCertificatesASN1PEM(certs []*x509.Certificate) ([]byte, error) {
	buffer := bytes.NewBuffer([]byte{})
	for _, cert := range certs {
		err := pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			return nil, fmt.Errorf("failed to encode certificate: %v", err)
		}
	}

	return buffer.Bytes(), nil
}
