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
	"crypto"
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
		*ec = EllipticCurveDefault
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
	EllipticCurveDefault = EllipticCurveP521

	defaultRSAlength int = 2048
)

func AllSupportedCurves() []EllipticCurve {
	return []EllipticCurve{EllipticCurveP521, EllipticCurveP224, EllipticCurveP256, EllipticCurveP384}
}
func AllSupportedKeySizes() []int {
	return []int{512, 1024, 2048, 4096, 8192}
}

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

func (kt *KeyType) X509Type() x509.PublicKeyAlgorithm {
	switch *kt {
	case KeyTypeRSA:
		return x509.RSA
	case KeyTypeECDSA:
		return x509.ECDSA
	}
	return x509.UnknownPublicKeyAlgorithm
}

//Set the key type via a string
func (kt *KeyType) Set(value string) error {
	switch strings.ToLower(value) {
	case "rsa":
		*kt = KeyTypeRSA
		return nil
	case "ecdsa", "ec", "ecc":
		*kt = KeyTypeECDSA
		return nil
	}
	return fmt.Errorf("unknow key type: %s", value) //todo: check all calls
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
// CSR is pem encoded Certificate Signed Request
type Request struct {
	Subject            pkix.Name
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
	Attributes         []pkix.AttributeTypeAndValueSET
	SignatureAlgorithm x509.SignatureAlgorithm
	PublicKeyAlgorithm x509.PublicKeyAlgorithm //deprecated
	FriendlyName       string
	KeyType            KeyType
	KeyLength          int
	KeyCurve           EllipticCurve
	CSR                []byte //should be pem encoded CSR
	PrivateKey         crypto.Signer
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
//please use method Request.GenerateCSR()
// todo: remove usage from all libraries
//deprecated
func GenerateRequest(request *Request, privateKey crypto.Signer) error {
	pk := request.PrivateKey
	request.PrivateKey = privateKey
	err := request.GenerateCSR()
	request.PrivateKey = pk
	return err
}

func (request *Request) GenerateCSR() error {
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject = request.Subject
	certificateRequest.DNSNames = request.DNSNames
	certificateRequest.EmailAddresses = request.EmailAddresses
	certificateRequest.IPAddresses = request.IPAddresses
	certificateRequest.Attributes = request.Attributes

	csr, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, request.PrivateKey)
	if err != nil {
		csr = nil
	}
	request.CSR = csr
	request.CSR = pem.EncodeToMemory(GetCertificateRequestPEMBlock(csr))
	return err
}

func (request *Request) GeneratePrivateKey() error {
	if request.PrivateKey != nil {
		return nil
	}
	var err error
	switch request.KeyType {
	case KeyTypeECDSA:
		request.PrivateKey, err = GenerateECDSAPrivateKey(request.KeyCurve)
	case KeyTypeRSA:
		if request.KeyLength == 0 {
			request.KeyLength = defaultRSAlength
		}
		request.PrivateKey, err = GenerateRSAPrivateKey(request.KeyLength)
	default:
		return fmt.Errorf("Unable to generate certificate request, key type %s is not supported", request.KeyType.String())
	}
	return err
}

func (request *Request) CheckCertificate(certPEM string) error {
	pemBlock, _ := pem.Decode([]byte(certPEM))
	if pemBlock == nil {
		return fmt.Errorf("invalid pem format certificate %s", certPEM)
	}
	if pemBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid pem type %s (expect CERTIFICATE)", pemBlock.Type)
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}
	if request.PrivateKey != nil {
		if request.KeyType.X509Type() != cert.PublicKeyAlgorithm {
			return fmt.Errorf("unmatched key type: %s, %s", request.KeyType.X509Type(), cert.PublicKeyAlgorithm)
		}
		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			certPubKey := cert.PublicKey.(*rsa.PublicKey)
			reqPubkey, ok := request.PrivateKey.Public().(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("request KeyType not matched with real PrivateKey type")
			}

			if certPubKey.N.Cmp(reqPubkey.N) != 0 {
				return fmt.Errorf("unmatched key modules")
			}
		case x509.ECDSA:
			certPubkey := cert.PublicKey.(*ecdsa.PublicKey)
			reqPubkey, ok := request.PrivateKey.Public().(*ecdsa.PublicKey)
			if !ok {
				return fmt.Errorf("request KeyType not matched with real PrivateKey type")
			}
			if certPubkey.X.Cmp(reqPubkey.X) != 0 {
				return fmt.Errorf("unmatched X for eliptic keys")
			}
		default:
			return fmt.Errorf("unknown key algorythm %d", cert.PublicKeyAlgorithm)
		}
	} else if len(request.CSR) != 0 {
		pemBlock, _ := pem.Decode(request.CSR)
		if pemBlock == nil {
			return fmt.Errorf("bad csr: %s", string(request.CSR))
		}
		csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
		if err != nil {
			return err
		}
		if cert.PublicKeyAlgorithm != csr.PublicKeyAlgorithm {
			return fmt.Errorf("unmatched key type: %s, %s", cert.PublicKeyAlgorithm, csr.PublicKeyAlgorithm)
		}
		switch csr.PublicKeyAlgorithm {
		case x509.RSA:
			certPubKey := cert.PublicKey.(*rsa.PublicKey)
			reqPubKey := csr.PublicKey.(*rsa.PublicKey)
			if certPubKey.N.Cmp(reqPubKey.N) != 0 {
				return fmt.Errorf("unmatched key modules")
			}
		case x509.ECDSA:
			certPubKey := cert.PublicKey.(*ecdsa.PublicKey)
			reqPubKey := csr.PublicKey.(*ecdsa.PublicKey)
			if certPubKey.X.Cmp(reqPubKey.X) != 0 {
				return fmt.Errorf("unmatched X for eliptic keys")
			}
		}
	}
	return nil
}

func publicKey(priv crypto.Signer) crypto.PublicKey {
	if priv != nil {
		return priv.Public()
	}
	return nil
}

func PublicKey(priv crypto.Signer) crypto.PublicKey {
	return publicKey(priv)
}

//GetPrivateKeyPEMBock gets the private key as a PEM data block
func GetPrivateKeyPEMBock(key interface{}) (*pem.Block, error) { //todo: change to crypto.Signer type
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
func GetEncryptedPrivateKeyPEMBock(key interface{}, password []byte) (*pem.Block, error) { //todo: change to crypto.Signer type
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
