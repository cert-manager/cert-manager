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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

//ChainOption represents the options to be used with the certificate chain
type ChainOption int

const (
	//ChainOptionRootLast specifies the root certificate should be in the last position of the chain
	ChainOptionRootLast ChainOption = iota
	//ChainOptionRootFirst specifies the root certificate should be in the first position of the chain
	ChainOptionRootFirst
	//ChainOptionIgnore specifies the chain should be ignored
	ChainOptionIgnore
)

//ChainOptionFromString converts the string to the corresponding ChainOption
func ChainOptionFromString(order string) ChainOption {
	switch strings.ToLower(order) {
	case "root-first":
		return ChainOptionRootFirst
	case "ignore":
		return ChainOptionIgnore
	default:
		return ChainOptionRootLast
	}
}

//PEMCollection represents a collection of PEM data
type PEMCollection struct {
	Certificate string   `json:",omitempty"`
	PrivateKey  string   `json:",omitempty"`
	Chain       []string `json:",omitempty"`
}

//NewPEMCollection creates a PEMCollection based on the data being passed in
func NewPEMCollection(certificate *x509.Certificate, privateKey interface{}, privateKeyPassword []byte) (*PEMCollection, error) {
	collection := PEMCollection{}
	if certificate != nil {
		collection.Certificate = string(pem.EncodeToMemory(GetCertificatePEMBlock(certificate.Raw)))
	}
	if privateKey != nil {
		var p *pem.Block
		var err error
		if privateKeyPassword != nil && len(privateKeyPassword) > 0 {
			p, err = GetEncryptedPrivateKeyPEMBock(privateKey, privateKeyPassword)
		} else {
			p, err = GetPrivateKeyPEMBock(privateKey)
		}
		if err != nil {
			return nil, err
		}
		collection.PrivateKey = string(pem.EncodeToMemory(p))
	}
	return &collection, nil
}

//PEMCollectionFromBytes creates a PEMCollection based on the data passed in
func PEMCollectionFromBytes(certBytes []byte, chainOrder ChainOption) (*PEMCollection, error) {
	var (
		current    []byte
		remaining  []byte
		p          *pem.Block
		cert       *x509.Certificate
		chain      []*x509.Certificate
		privPEM    string
		err        error
		collection *PEMCollection
	)
	current = certBytes

	for {
		p, remaining = pem.Decode(current)
		if p == nil {
			break
		}
		switch p.Type {
		case "CERTIFICATE":
			cert, err = x509.ParseCertificate(p.Bytes)
			if err != nil {
				return nil, err
			}
			chain = append(chain, cert)
		case "RSA PRIVATE KEY", "EC PRIVATE KEY":
			privPEM = string(current)
		}
		current = remaining
	}

	if len(chain) > 0 {
		switch chainOrder {
		case ChainOptionRootFirst:
			collection, err = NewPEMCollection(chain[len(chain)-1], nil, nil)
			if len(chain) > 1 && chainOrder != ChainOptionIgnore {
				for _, caCert := range chain[:len(chain)-1] {
					collection.AddChainElement(caCert)
				}
			}
		default:
			collection, err = NewPEMCollection(chain[0], nil, nil)
			if len(chain) > 1 && chainOrder != ChainOptionIgnore {
				for _, caCert := range chain[1:] {
					collection.AddChainElement(caCert)
				}
			}
		}
		if err != nil {
			return nil, err
		}
	} else {
		collection = &PEMCollection{}
	}
	collection.PrivateKey = privPEM

	return collection, nil
}

//AddPrivateKey adds a Private Key to the PEMCollection. Note that the collection can only contain one private key
func (col *PEMCollection) AddPrivateKey(privateKey interface{}, privateKeyPassword []byte) error {
	if col.PrivateKey != "" {
		return fmt.Errorf("The PEM Collection can only contain one private key")
	}
	var p *pem.Block
	var err error
	if privateKeyPassword != nil && len(privateKeyPassword) > 0 {
		p, err = GetEncryptedPrivateKeyPEMBock(privateKey, privateKeyPassword)
	} else {
		p, err = GetPrivateKeyPEMBock(privateKey)
	}
	if err != nil {
		return err
	}
	col.PrivateKey = string(pem.EncodeToMemory(p))
	return nil
}

//AddChainElement adds a chain element to the collection
func (col *PEMCollection) AddChainElement(certificate *x509.Certificate) error {
	if certificate == nil {
		return fmt.Errorf("Certificate cannot be nil")
	}
	pemChain := col.Chain
	pemChain = append(pemChain, string(pem.EncodeToMemory(GetCertificatePEMBlock(certificate.Raw))))
	col.Chain = pemChain
	return nil
}
