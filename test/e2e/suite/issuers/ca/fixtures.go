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

package ca

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// These hardcoded certificates are generated using cert-manager.
// The YAML used to create these certificates is at the bottom of this file.
// Each cert was created and then copied by hand, with intermediate 2 having its
// chain in 'tls.crt' trimmed manually

// rootCert is a hardcoded issuer certificate. Its dumped value is below:
//
//	Version: 3 (0x2)
//	Serial Number:
//	    f2:68:07:5e:fb:b1:5e:74:ab:27:cf:a5:7c:03:2f:b8
//	Signature Algorithm: ecdsa-with-SHA256
//	Issuer: C = UK, O = cert-manager, CN = cert-manager testing CA
//	Validity
//	    Not Before: Nov 14 13:13:15 2023 GMT
//	    Not After : Oct 21 13:13:15 2123 GMT
//	Subject: C = UK, O = cert-manager, CN = cert-manager testing CA
//	Subject Public Key Info:
//	    Public Key Algorithm: id-ecPublicKey
//	        Public-Key: (256 bit)
//	        pub:
//	            04:d9:d7:61:40:b6:5a:e3:17:3e:8f:c4:27:49:cf:
//	            6b:7d:35:24:d4:b7:c1:18:57:2c:6e:5d:aa:3c:ae:
//	            a4:75:6d:f6:f6:d1:10:7a:0d:3e:0a:70:b9:3f:98:
//	            5c:70:db:17:49:d2:9c:4e:9c:2b:3f:cc:45:2e:d4:
//	            31:3c:3d:6a:90
//	        ASN1 OID: prime256v1
//	        NIST CURVE: P-256
//	X509v3 extensions:
//	    X509v3 Key Usage: critical
//	        Digital Signature, Key Encipherment, Certificate Sign
//	    X509v3 Basic Constraints: critical
//	        CA:TRUE
//	    X509v3 Subject Key Identifier:
//	        DA:C7:45:E4:F1:67:F2:5F:F4:02:49:37:5A:F9:A9:C4:92:E7:65:F8
//
// Signature Algorithm: ecdsa-with-SHA256
// Signature Value:
//
//	30:44:02:20:7f:5a:00:45:00:5f:e1:bc:b6:36:4f:30:be:24:
//	7f:ce:01:e6:61:12:95:41:3a:69:1b:63:b7:63:13:d5:34:5d:
//	02:20:1d:52:3e:11:e5:f6:54:31:aa:93:f0:9d:81:9b:01:40:
//	8a:c2:0d:c4:ed:fc:23:cd:39:19:42:7e:a4:7d:c6:4a
const rootCert = `-----BEGIN CERTIFICATE-----
MIIBzjCCAXWgAwIBAgIRAPJoB177sV50qyfPpXwDL7gwCgYIKoZIzj0EAwIwRjEL
MAkGA1UEBhMCVUsxFTATBgNVBAoTDGNlcnQtbWFuYWdlcjEgMB4GA1UEAxMXY2Vy
dC1tYW5hZ2VyIHRlc3RpbmcgQ0EwIBcNMjMxMTE0MTMxMzE1WhgPMjEyMzEwMjEx
MzEzMTVaMEYxCzAJBgNVBAYTAlVLMRUwEwYDVQQKEwxjZXJ0LW1hbmFnZXIxIDAe
BgNVBAMTF2NlcnQtbWFuYWdlciB0ZXN0aW5nIENBMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAE2ddhQLZa4xc+j8QnSc9rfTUk1LfBGFcsbl2qPK6kdW329tEQeg0+
CnC5P5hccNsXSdKcTpwrP8xFLtQxPD1qkKNCMEAwDgYDVR0PAQH/BAQDAgKkMA8G
A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNrHReTxZ/Jf9AJJN1r5qcSS52X4MAoG
CCqGSM49BAMCA0cAMEQCIH9aAEUAX+G8tjZPML4kf84B5mESlUE6aRtjt2MT1TRd
AiAdUj4R5fZUMaqT8J2BmwFAisINxO38I805GUJ+pH3GSg==
-----END CERTIFICATE-----
`

const rootKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJpxHkhfBgd6I8P03Ny3nN14uJESxJgb+RZRMpNbZwxmoAoGCCqGSM49
AwEHoUQDQgAE2ddhQLZa4xc+j8QnSc9rfTUk1LfBGFcsbl2qPK6kdW329tEQeg0+
CnC5P5hccNsXSdKcTpwrP8xFLtQxPD1qkA==
-----END EC PRIVATE KEY-----
`

func newSigningKeypairSecret(name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		StringData: map[string]string{
			corev1.TLSCertKey:       rootCert,
			corev1.TLSPrivateKeyKey: rootKey,
		},
	}
}

// issuer1Cert is a hardcoded issuer certificate. Its dumped value is below:
//
//	Version: 3 (0x2)
//	Serial Number:
//	    e9:8f:6f:02:16:60:5f:0a:9c:60:6e:e5:2c:c2:89:c4
//	Signature Algorithm: ecdsa-with-SHA256
//	Issuer: C = UK, O = cert-manager, CN = cert-manager testing CA
//	Validity
//	    Not Before: Nov 14 13:13:20 2023 GMT
//	    Not After : Oct 21 13:13:20 2122 GMT
//	Subject: C = UK, O = cert-manager, CN = cert-manager testing Issuer
//	Subject Public Key Info:
//	    Public Key Algorithm: id-ecPublicKey
//	        Public-Key: (256 bit)
//	        pub:
//	            04:10:ce:5a:a1:67:6d:56:50:9a:4f:a5:d3:fc:6a:
//	            06:dd:80:0f:df:57:93:fc:e1:a3:01:c2:32:05:61:
//	            7d:82:a5:61:96:a0:42:61:af:6f:df:c4:02:bf:21:
//	            a5:a7:75:ce:37:69:db:1d:6e:6a:cc:af:3a:e6:c2:
//	            e6:92:52:e4:f1
//	        ASN1 OID: prime256v1
//	        NIST CURVE: P-256
//	X509v3 extensions:
//	    X509v3 Key Usage: critical
//	        Digital Signature, Key Encipherment, Certificate Sign
//	    X509v3 Basic Constraints: critical
//	        CA:TRUE
//	    X509v3 Subject Key Identifier:
//	        C5:9C:69:C7:DB:59:72:5A:A7:53:44:66:FF:81:4E:89:BC:68:56:34
//	    X509v3 Authority Key Identifier:
//	        DA:C7:45:E4:F1:67:F2:5F:F4:02:49:37:5A:F9:A9:C4:92:E7:65:F8
//
// Signature Algorithm: ecdsa-with-SHA256
// Signature Value:
//
// 30:45:02:20:16:53:d3:c3:0e:3e:35:23:08:e3:0b:c5:82:a3:
// ab:59:5c:2d:f2:d4:06:7c:85:11:3f:5b:0e:c0:e7:37:7a:2b:
// 02:21:00:ac:57:c5:a4:e4:42:93:31:03:4a:d2:20:de:da:f3:
// 40:af:46:52:df:e3:2f:1c:fc:e9:8c:3f:82:47:aa:c5:27
const issuer1Cert = `-----BEGIN CERTIFICATE-----
MIIB9DCCAZqgAwIBAgIRAOmPbwIWYF8KnGBu5SzCicQwCgYIKoZIzj0EAwIwRjEL
MAkGA1UEBhMCVUsxFTATBgNVBAoTDGNlcnQtbWFuYWdlcjEgMB4GA1UEAxMXY2Vy
dC1tYW5hZ2VyIHRlc3RpbmcgQ0EwIBcNMjMxMTE0MTMxMzIwWhgPMjEyMjEwMjEx
MzEzMjBaMEoxCzAJBgNVBAYTAlVLMRUwEwYDVQQKEwxjZXJ0LW1hbmFnZXIxJDAi
BgNVBAMTG2NlcnQtbWFuYWdlciB0ZXN0aW5nIElzc3VlcjBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABBDOWqFnbVZQmk+l0/xqBt2AD99Xk/zhowHCMgVhfYKlYZag
QmGvb9/EAr8hpad1zjdp2x1uasyvOubC5pJS5PGjYzBhMA4GA1UdDwEB/wQEAwIC
pDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTFnGnH21lyWqdTRGb/gU6JvGhW
NDAfBgNVHSMEGDAWgBTax0Xk8WfyX/QCSTda+anEkudl+DAKBggqhkjOPQQDAgNI
ADBFAiAWU9PDDj41IwjjC8WCo6tZXC3y1AZ8hRE/Ww7A5zd6KwIhAKxXxaTkQpMx
A0rSIN7a80CvRlLf4y8c/OmMP4JHqsUn
-----END CERTIFICATE-----
`

const issuer1Key = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOgqbZ1Z5PVkxq4s89+CZaE5hwMNQiW9B1ldCwDFXaN9oAoGCCqGSM49
AwEHoUQDQgAEEM5aoWdtVlCaT6XT/GoG3YAP31eT/OGjAcIyBWF9gqVhlqBCYa9v
38QCvyGlp3XON2nbHW5qzK865sLmklLk8Q==
-----END EC PRIVATE KEY-----
`

func newSigningIssuer1KeypairSecret(name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		StringData: map[string]string{
			corev1.TLSCertKey:       issuer1Cert + rootCert,
			corev1.TLSPrivateKeyKey: issuer1Key,
		},
	}
}

// issuer2Cert is a hardcoded issuer certificate. Its dumped value is below:
//
//	Version: 3 (0x2)
//	Serial Number:
//	    ad:3c:69:dd:89:4a:a6:5c:e0:12:9e:1b:a2:3a:28:d8
//	Signature Algorithm: ecdsa-with-SHA256
//	Issuer: C = UK, O = cert-manager, CN = cert-manager testing Issuer
//	Validity
//	    Not Before: Nov 14 13:13:40 2023 GMT
//	    Not After : Oct 21 13:13:40 2121 GMT
//	Subject: C = UK, O = cert-manager, CN = cert-manager testing Issuer Level 2
//	Subject Public Key Info:
//	    Public Key Algorithm: id-ecPublicKey
//	        Public-Key: (256 bit)
//	        pub:
//	            04:dc:8e:15:e3:e7:cc:bb:18:37:c9:bc:d3:73:a6:
//	            a9:e6:6f:5d:b1:ea:32:45:af:7f:3d:7e:9a:ff:5a:
//	            c6:6e:c2:79:fd:8d:57:c8:25:47:9d:16:e1:06:4e:
//	            26:2c:01:e0:df:ac:f6:c8:ef:06:72:51:9e:55:88:
//	            7d:f1:0f:d4:e7
//	        ASN1 OID: prime256v1
//	        NIST CURVE: P-256
//	X509v3 extensions:
//	    X509v3 Key Usage: critical
//	        Digital Signature, Key Encipherment, Certificate Sign
//	    X509v3 Basic Constraints: critical
//	        CA:TRUE
//	    X509v3 Subject Key Identifier:
//	        4D:6E:AA:29:39:75:2E:A1:E0:6A:4E:F2:F4:E4:07:B4:99:D5:23:8B
//	    X509v3 Authority Key Identifier:
//	        C5:9C:69:C7:DB:59:72:5A:A7:53:44:66:FF:81:4E:89:BC:68:56:34
//
// Signature Algorithm: ecdsa-with-SHA256
// Signature Value:
//
//	30:44:02:20:4a:78:8d:cb:56:b9:12:d1:0b:dd:bd:77:f1:28:
//	14:71:b3:e1:6e:30:a6:27:73:ba:de:c9:a8:53:9e:c3:43:cb:
//	02:20:68:92:6b:13:72:35:18:70:3e:66:cb:e1:ca:b5:47:0f:
//	d9:16:5e:1a:00:2d:58:61:a4:05:29:08:a1:ea:c8:87
const issuer2Cert = `-----BEGIN CERTIFICATE-----
MIIB/zCCAaagAwIBAgIRAK08ad2JSqZc4BKeG6I6KNgwCgYIKoZIzj0EAwIwSjEL
MAkGA1UEBhMCVUsxFTATBgNVBAoTDGNlcnQtbWFuYWdlcjEkMCIGA1UEAxMbY2Vy
dC1tYW5hZ2VyIHRlc3RpbmcgSXNzdWVyMCAXDTIzMTExNDEzMTM0MFoYDzIxMjEx
MDIxMTMxMzQwWjBSMQswCQYDVQQGEwJVSzEVMBMGA1UEChMMY2VydC1tYW5hZ2Vy
MSwwKgYDVQQDEyNjZXJ0LW1hbmFnZXIgdGVzdGluZyBJc3N1ZXIgTGV2ZWwgMjBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABNyOFePnzLsYN8m803OmqeZvXbHqMkWv
fz1+mv9axm7Cef2NV8glR50W4QZOJiwB4N+s9sjvBnJRnlWIffEP1OejYzBhMA4G
A1UdDwEB/wQEAwICpDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRNbqopOXUu
oeBqTvL05Ae0mdUjizAfBgNVHSMEGDAWgBTFnGnH21lyWqdTRGb/gU6JvGhWNDAK
BggqhkjOPQQDAgNHADBEAiBKeI3LVrkS0QvdvXfxKBRxs+FuMKYnc7reyahTnsND
ywIgaJJrE3I1GHA+ZsvhyrVHD9kWXhoALVhhpAUpCKHqyIc=
-----END CERTIFICATE-----
`

const issuer2Key = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKAcZcHAM0aunfX5bZcTGW6p5FR0PCH+mJT7R5SgKFaOoAoGCCqGSM49
AwEHoUQDQgAE3I4V4+fMuxg3ybzTc6ap5m9dseoyRa9/PX6a/1rGbsJ5/Y1XyCVH
nRbhBk4mLAHg36z2yO8GclGeVYh98Q/U5w==
-----END EC PRIVATE KEY-----
`

func newSigningIssuer2KeypairSecret(name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		StringData: map[string]string{
			corev1.TLSCertKey:       issuer2Cert + issuer1Cert + rootCert,
			corev1.TLSPrivateKeyKey: issuer2Key,
		},
	}
}

// YAML for creating the hardcoded certificates in this file:

/*
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}

---

apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: root-cert
spec:
  isCA: true
  commonName: cert-manager testing CA
  secretName: root-secret
  duration: 876000h # 365 days * 100 years
  subject:
    organizations:
    - cert-manager
    countries:
    - UK
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: selfsigned-issuer
    kind: ClusterIssuer
    group: cert-manager.io

---

apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: root-ca-issuer
spec:
  ca:
    secretName: root-secret

---

apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: intermediate-cert-1
spec:
  isCA: true
  commonName: cert-manager testing Issuer
  secretName: intermediate-cert-1-secret
  duration: 867240h # 365 days * 99 years
  subject:
    organizations:
    - cert-manager
    countries:
    - UK
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: root-ca-issuer
    kind: Issuer
    group: cert-manager.io

---

apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: intermediate-cert-1-issuer
spec:
  ca:
    secretName: intermediate-cert-1-secret

---

apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: intermediate-cert-2
spec:
  isCA: true
  commonName: cert-manager testing Issuer Level 2
  secretName: intermediate-cert-2-secret
  duration: 858480h # 365 days * 98 years
  subject:
    organizations:
    - cert-manager
    countries:
    - UK
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: intermediate-cert-1-issuer
    kind: Issuer
    group: cert-manager.io
*/
