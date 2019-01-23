/*
 * Copyright 2018 Venafi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

//EllipticCurve represents the types of supported elliptic curves
type EllipticCurve int

func (ec *EllipticCurve) String() string {
	switch *ec {
	case EllipticCurveP521:
		return "P521"
	case EllipticCurveP384:
		return "P384"
	case EllipticCurveP256:
		return "P256"
	case EllipticCurveP224:
		return "P224"
	default:
		return ""
	}
}

//Set the elliptic cuve value via a string
func (ec *EllipticCurve) Set(value string) error {
	switch strings.ToLower(value) {
	case "p521":
		*ec = EllipticCurveP521
	case "p384":
		*ec = EllipticCurveP384
	case "p256":
		*ec = EllipticCurveP256
	case "p224":
		*ec = EllipticCurveP224
	default:
		*ec = EllipticCurveP521
	}

	return nil
}

const (
	//EllipticCurveP521 represents the P521 curve
	EllipticCurveP521 EllipticCurve = iota
	//EllipticCurveP224 represents the P224 curve
	EllipticCurveP224
	//EllipticCurveP256 represents the P256 curve
	EllipticCurveP256
	//EllipticCurveP384 represents the P384 curve
	EllipticCurveP384
)

//KeyType represents the types of supported keys
type KeyType int

func (kt *KeyType) String() string {
	switch *kt {
	case KeyTypeRSA:
		return "RSA"
	case KeyTypeECDSA:
		return "ECDSA"
	default:
		return ""
	}
}

//Set the key type via a string
func (kt *KeyType) Set(value string) error {
	switch strings.ToLower(value) {
	case "rsa":
		*kt = KeyTypeRSA
	case "ecdsa":
		*kt = KeyTypeECDSA
	default:
		*kt = KeyTypeECDSA
	}

	return nil
}

const (
	//KeyTypeRSA represents a key type of RSA
	KeyTypeRSA KeyType = iota
	//KeyTypeECDSA represents a key type of ECDSA
	KeyTypeECDSA
)

type CSrOriginOption int

const (
	LocalGeneratedCSR CSrOriginOption = iota // local generation is default.
	ServiceGeneratedCSR
	UserProvidedCSR
)

//Request contains data needed to generate a certificate request
type Request struct {
	Subject            pkix.Name
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
	Attributes         []pkix.AttributeTypeAndValueSET
	SignatureAlgorithm x509.SignatureAlgorithm
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	FriendlyName       string
	KeyType            KeyType
	KeyLength          int
	KeyCurve           EllipticCurve
	CSR                []byte
	PrivateKey         interface{}
	CsrOrigin          CSrOriginOption
	PickupID           string
	ChainOption        ChainOption
	KeyPassword        string
	FetchPrivateKey    bool
	Thumbprint         string /* this one is here because *Request is used in RetrieveCertificate(),
	   it should be refactored so that RetrieveCertificate() uses
	   some abstract search object, instead of *Request{PickupID} */
	Timeout time.Duration
}

type RevocationRequest struct {
	CertificateDN string
	Thumbprint    string
	Reason        string
	Comments      string
	Disable       bool
}

type RenewalRequest struct {
	CertificateDN      string // these fields are for certificate lookup on remote
	Thumbprint         string
	CertificateRequest *Request // here CSR should be filled
}

type ImportRequest struct {
	PolicyDN             string            `json:",omitempty"`
	ObjectName           string            `json:",omitempty"`
	CertificateData      string            `json:",omitempty"`
	PrivateKeyData       string            `json:",omitempty"`
	Password             string            `json:",omitempty"`
	Reconcile            bool              `json:",omitempty"`
	CASpecificAttributes map[string]string `json:",omitempty"`
}

type ImportResponse struct {
	CertificateDN      string `json:",omitempty"`
	CertificateVaultId int    `json:",omitempty"`
	Guid               string `json:",omitempty"`
	PrivateKeyVaultId  int    `json:",omitempty"`
}

//GenerateRequest generates a certificate request
func GenerateRequest(request *Request, privateKey interface{}) error {
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject = request.Subject
	certificateRequest.DNSNames = request.DNSNames
	certificateRequest.EmailAddresses = request.EmailAddresses
	certificateRequest.IPAddresses = request.IPAddresses
	certificateRequest.Attributes = request.Attributes

	csr, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, privateKey)
	if err != nil {
		csr = nil
	}
	request.CSR = csr

	return err
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func PublicKey(priv interface{}) interface{} {
	return publicKey(priv)
}

//GetPrivateKeyPEMBock gets the private key as a PEM data block
func GetPrivateKeyPEMBock(key interface{}) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, fmt.Errorf("Unable to format Key")
	}
}

//GetEncryptedPrivateKeyPEMBock gets the private key as an encrypted PEM data block
func GetEncryptedPrivateKeyPEMBock(key interface{}, password []byte) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k), password, x509.PEMCipherAES256)
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", b, password, x509.PEMCipherAES256)
	default:
		return nil, fmt.Errorf("Unable to format Key")
	}
}

//GetCertificatePEMBlock gets the certificate as a PEM data block
func GetCertificatePEMBlock(cert []byte) *pem.Block {
	return &pem.Block{Type: "CERTIFICATE", Bytes: cert}
}

//GetCertificateRequestPEMBlock gets the certificate request as a PEM data block
func GetCertificateRequestPEMBlock(request []byte) *pem.Block {
	return &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}
}

//GenerateECDSAPrivateKey generates a new ecdsa private key using the curve specified
func GenerateECDSAPrivateKey(curve EllipticCurve) (*ecdsa.PrivateKey, error) {
	var priv *ecdsa.PrivateKey
	var c elliptic.Curve
	var err error

	switch curve {
	case EllipticCurveP521:
		c = elliptic.P521()
	case EllipticCurveP384:
		c = elliptic.P384()
	case EllipticCurveP256:
		c = elliptic.P256()
	case EllipticCurveP224:
		c = elliptic.P224()
	}

	priv, err = ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

//GenerateRSAPrivateKey generates a new rsa private key using the size specified
func GenerateRSAPrivateKey(size int) (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func NewRequest(cert *x509.Certificate) *Request {
	req := &Request{}
	// 1st fill with *cert content

	req.Subject = cert.Subject
	req.DNSNames = cert.DNSNames
	req.EmailAddresses = cert.EmailAddresses
	req.IPAddresses = cert.IPAddresses
	req.SignatureAlgorithm = cert.SignatureAlgorithm
	req.PublicKeyAlgorithm = cert.PublicKeyAlgorithm
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		req.KeyType = KeyTypeRSA
		req.KeyLength = pub.N.BitLen()
	case *ecdsa.PublicKey:
		req.KeyType = KeyTypeECDSA
		req.KeyLength = pub.Curve.Params().BitSize
		// TODO: req.KeyCurve = pub.Curve.Params().Name...
	default: // case *dsa.PublicKey:
		// vcert only works with RSA & ECDSA
	}
	return req
}
