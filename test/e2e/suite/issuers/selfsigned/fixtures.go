/*
Copyright 2020 The cert-manager Authors.

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

package selfsigned

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

var rootRSAKeySigner, rootECKeySigner, rootEd25519Signer crypto.Signer

func init() {
	var err error
	rootRSAKeySigner, err = pki.DecodePrivateKeyBytes(rootRSAKey)
	if err != nil {
		panic(err)
	}

	rootECKeySigner, err = pki.DecodePrivateKeyBytes(rootECKey)
	if err != nil {
		panic(err)
	}

	rootEd25519Signer, err = pki.DecodePrivateKeyBytes(rootEd25519Key)
	if err != nil {
		panic(err)
	}
}

var (
	rootRSAKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAz5DYA7iEBFq/SrCOTsjiYSHlHbTUdLyzselos5cE2++Huon3
InPqMupiDoS8/Qr9srnoKnah7aKB3sY7GlXdg85zcIbQIKocymsRy/GPbEEpfTRG
1yfihUuEM+EBvQFX9Hs0Ut5bHOH6CC88jVebWotpZiphkQnlsGxhcPe091LgYYg1
HPxm+KHjp/RnbBWQIahOmxtfwc7vixrYNrJSPMCxYaU7ltkaIxIeMMSd/3J6TZNy
MTJWiiGg4tpCD+eDbVPlFbN5kpOXVzOfC4ZWv21l8cWrFDmp5oh37UgK3E2+QSNt
OdmXpbL0K2GfR3HA55LlOowntIU1fLWCniN/8wIDAQABAoIBAQCYvGvIKSG0FpbG
vi6pmLbEZO20s1jW4fiUxT2PUWR49sR4pocdahB/EOvA5TowNcNDnftSK+Ox+q/4
HwRkt6R+Fg/qULmcH7F53dnFqeYw8a42/J3YOvg7v7rzdfISg4eWVobFJ+wBz+Nt
3FyBYWLm+MlBLZSH5rGG5em59/zJNHWIhH+oQPfCxAkYEvd8tXOTUzjhqvEfjaJy
FZghnT9xto4MwDdNCPbtzdNjTMhiv0AHkcZGGtRJfkehXX2qhXOQ2UzzO9XrMZnv
5KgYf+bXKJsyS3SPl6TTl7vg2gKBciRvsdFhMy5I5GyIADrEDJnNNmXQRtiaFLfd
k/aqfPT5AoGBAPquMouZUbVS/Qh+qbls7G4zAuznfCiqdctcKmUGPRP4sTTjWdUp
fjI+UTt1e8hncmr4RY7Oa9kUV/kDwzS5spUZZ+u0PczS3XKxOwNOleoH00dfc9vt
cxctHdPdDTndRi8Z4k3m931jIX7jB/Pyx8qeNYB3pj0k3ThktwMbAVLnAoGBANP4
beI5zpbvtAdExJcuxx2mRDGF0lIdKC0bvQaeqM3Lwqnmc0Fz1dbP7KXDa+SdJWPd
res+NHPZoEPeEJuDTSngXOLNECZe4Ja9frn1TeY858vMJBwIkyc8zu+sgXxjQUM+
TWUlTUhtXyybkRnxAEny4OT2TTgmXITJaKOmV1UVAoGAHaXSlo4YitB42rNYUXTf
dZ0U4H30Qj7+1YFeBjq5qI4GL1IgQsS4hyq1osmfTTFm593bJCunt7HfQbU/NhIs
W9P4ZXkYwgvCYxkw+JAnzNkGFO/mHQG1Ve1hFLiVIt3XuiRejoYdiTfbM02YmDKD
jKQvgbUk9SBSBaRrvLNJ8csCgYAYnrZEnGo+ZcEHRxl+ZdSCwRkSl3SCTRiphJtD
9ZGttYj6quWgKJAhzyyxZC1X9FivbMQSmrsE6bYPq+9J4MpJnuGrBh5mFocHeyMI
/lD5+QEDTsay6twMpqdydxrjE7Q01zuuD9MWIn33dGo6FR/vduJgNatqZipA0hPx
ThS+sQKBgQDh0+cVo1mfYiCkp3IQPB8QYiJ/g2/UBk6pH8ZZDZ+A5td6NveiWO1y
wTEUWkX2qyz9SLxWDGOhdKqxNrLCUSYSOV/5/JQEtBm6K50ArFtrY40JP/T/5KvM
tSK2ayFX1wQ3PuEmewAogy/20tWo80cr556AXA62Utl2PzLK30Db8w==
-----END RSA PRIVATE KEY-----`)

	rootECKey = []byte(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAsPt8R7dwT/sGem7sKEkFVXtGh53YI1Zn8h36VCadsarasU+377pC
R8DABinwP/8uBUsurS6x3U1eHykifh3VrTCgBwYFK4EEACOhgYkDgYYABAEFHm6q
H93j9Lw3gg3Z47vxMaGG5Oq1EHmSWQpb6rD8LGeDLeDY6YvqfGj0AuriAHemfaFC
QRaEZO9OlMU8DNvkPwAWNp1+i/hjbti6Hv/j8ZAwM6aKNtCyiSmRCcaLMbjL4oFW
Fnu7/uKI2glvtykTMk19eFuDY3Mv9wB54Cjk9NrQWg==
-----END EC PRIVATE KEY-----`)

	rootEd25519Key = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDILZEyxoAbFmJJFKSGuzFxBB1Q1cygU+g4a9dEZrVqS
-----END PRIVATE KEY-----`)
)

func newPrivateKeySecret(name, namespace string, keyData []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: keyData,
		},
	}
}

func generateRSACSR() ([]byte, error) {
	csr, err := generateCSR(rootRSAKeySigner, x509.SHA256WithRSA)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func generateECCSR() ([]byte, error) {
	csr, err := generateCSR(rootECKeySigner, x509.ECDSAWithSHA256)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func generateEd25519CSR() ([]byte, error) {
	csr, err := generateCSR(rootEd25519Signer, x509.PureEd25519)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func generateCSR(privateKey crypto.Signer, alg x509.SignatureAlgorithm) ([]byte, error) {
	var uris []*url.URL
	for _, uri := range []string{
		"spiffe://foo.foo.example.net",
		"spiffe://foo.bar.example.net",
	} {
		parsed, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}
		uris = append(uris, parsed)
	}

	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: "my-common-name",
	}.ToRDNSequence())
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: alg,
		URIs:               uris,

		DNSNames: []string{"dnsName1.co", "dnsName2.ninja"},
		IPAddresses: []net.IP{
			[]byte{8, 8, 8, 8},
			[]byte{1, 1, 1, 1},
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, err
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csr, nil
}
