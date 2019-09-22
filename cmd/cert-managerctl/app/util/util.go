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

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/cmd/cert-managerctl/app/apis/cert-managerctl/v1alpha1"
)

func ParsePrivateKeyFile(path string) (*v1alpha1.KeyBundle, error) {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return DecodePrivateKeyBytes(keyBytes)
}

// DecodePrivateKeyBytes will decode a PEM encoded private key into a crypto.Signer.
// It supports ECDSA and RSA private keys only. All other types will return err.
func DecodePrivateKeyBytes(keyBytes []byte) (*v1alpha1.KeyBundle, error) {
	// decode the private key pem
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("error decoding private key PEM block")
	}

	var err error
	var key interface{}
	var sigAlgo x509.SignatureAlgorithm
	var pubAlgo x509.PublicKeyAlgorithm

	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing pkcs#8 private key: %s", err)
		}

		_, ok := key.(*rsa.PrivateKey)
		if !ok {
			_, ok = key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("error determining private key type")
			}

			sigAlgo = x509.ECDSAWithSHA256
			pubAlgo = x509.ECDSA

			break
		}

		sigAlgo = x509.SHA256WithRSA
		pubAlgo = x509.RSA

	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing ecdsa private key: %s", err)
		}

		sigAlgo = x509.ECDSAWithSHA256
		pubAlgo = x509.ECDSA

		break

	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing rsa private key: %s", err)
		}

		sigAlgo = x509.SHA256WithRSA
		pubAlgo = x509.RSA

	default:
		return nil, fmt.Errorf("unknown private key type: %s", block.Type)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("error parsing pkcs#8 private key: invalid key type")
	}

	return &v1alpha1.KeyBundle{
		PrivateKey:         signer,
		SignatureAlgorithm: sigAlgo,
		PublicKeyAlgorithm: pubAlgo,
	}, nil
}

func DefaultGenerateObjectMeta(opts metav1.ObjectMeta) metav1.ObjectMeta {
	if len(opts.Name) == 0 {
		return metav1.ObjectMeta{
			GenerateName: "cert-managerctl-",
			Namespace:    opts.Namespace,
		}
	}

	return metav1.ObjectMeta{
		Name:      opts.Name,
		Namespace: opts.Namespace,
	}
}

func ParseURLs(urlStrs []string) ([]*url.URL, error) {
	var uris []*url.URL
	var errs []string

	for _, uriStr := range urlStrs {
		uri, err := url.Parse(uriStr)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}

		uris = append(uris, uri)
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("failed to parse URIs: %s",
			strings.Join(errs, ", "))
	}

	return uris, nil
}

func ParseIPAddresses(ipsS []string) []net.IP {
	var ipAddresses []net.IP

	for _, ipName := range ipsS {
		ip := net.ParseIP(ipName)
		if ip != nil {
			ipAddresses = append(ipAddresses, ip)
		}
	}

	return ipAddresses
}

func FileExists(path string) (bool, error) {
	_, err := os.Stat("/path/to/whatever")
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}
