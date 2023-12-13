/*
Copyright 2023 The cert-manager Authors.

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

package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"reflect"
	"testing"
)

func extractSANsFromCertificate(t *testing.T, certDER string) pkix.Extension {
	block, rest := pem.Decode([]byte(certDER))
	if len(rest) > 0 {
		t.Fatal("Expected no rest")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("certificate.ParseCertificate returned an error: %v", err)
	}

	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oidExtensionSubjectAltName) {
			return extension
		}
	}

	t.Fatal("Could not find SANs in certificate")
	return pkix.Extension{}
}

func extractSANsFromCertificateRequest(t *testing.T, csrDER string) pkix.Extension {
	block, rest := pem.Decode([]byte(csrDER))
	if len(rest) > 0 {
		t.Fatal("Expected no rest")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("certificate.ParseCertificate returned an error: %v", err)
	}

	for _, extension := range csr.Extensions {
		if extension.Id.Equal(oidExtensionSubjectAltName) {
			return extension
		}
	}

	t.Fatal("Could not find SANs in certificate")
	return pkix.Extension{}
}

func generateOtherName(t *testing.T, val UniversalValue) asn1.RawValue {
	bytes, err := MarshalUniversalValue(val)
	if err != nil {
		t.Fatalf("MarshalUniversalValue returned an error: %v", err)
	}

	rv := asn1.RawValue{
		Tag:        0,
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Bytes:      bytes,
	}

	fullBytes, err := asn1.Marshal(rv)
	if err != nil {
		t.Fatalf("asn1.Marshal returned an error: %v", err)
	}
	rv.FullBytes = fullBytes

	return rv
}

func TestMarshalAndUnmarshalSANs(t *testing.T) {
	type testCase struct {
		hasSubject   bool
		gns          GeneralNames
		sanExtension pkix.Extension
	}

	testcases := []testCase{
		{
			hasSubject: true,
			gns: GeneralNames{
				OtherNames: []OtherName{
					{
						TypeID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
						Value: generateOtherName(t, UniversalValue{
							Utf8String: "3goats@acme.com",
						}),
					},
				},
			},
			sanExtension: extractSANsFromCertificateRequest(t, `-----BEGIN CERTIFICATE REQUEST-----
MIICnDCCAYQCAQAwGjEYMBYGA1UEAwwPM2dvYXRzLmFjbWUuY29tMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAsMWNfjdYm8jr57nMrs3ubdS20GDTcLzyu2KQqhGFCMY7COaVCP9ndZVv
nFv7q2LRB8P5MA9ROYNAXqgrF9CatWiaL1WaB3A5VICj3M9iQnaPw7XpZJW+GvZTltDOWhW0kPSW
3aQidsVocPGol2Co1qVrD3GXu610+EgDkSkyEI2/rMJPtjYf9OSuZoHeZn8xzny6+nlFQKVhHQ16
3blPkkrKMe6KQApGs49x9HvQAUT7UfMIb4btQMW/6+wQfWC/t0y0IsRU0fLiOr6+r4jYKAhewSEF
Pii4y4ds9GK3ZziaXPxPlDonyzezePJUiTRHJY/HEHnkmo+VX3rpzVdTFwIDAQABoD0wOwYJKoZI
hvcNAQkOMS4wLDAqBgNVHREEIzAhoB8GCisGAQQBgjcUAgOgEQwPM2dvYXRzQGFjbWUuY29tMA0G
CSqGSIb3DQEBCwUAA4IBAQABLr+BhRi4/Kb86kt2aO7J3FxdlPaEG6aUCxcbXkW5sGzxcmT2BSJQ
k2zDDu6t4paFV8sdWspb3IFdnF4loG/PKOaBOjXcfyaBk5mXWIcb7N/QhKHtgc79yPf3ywW/+FUy
97aNCtcyGuz54GRgGI/VValnQBjqoZ7cqPdb+TmSu8Zmn3hfF5Evs9AKWLaHBkPcb8//qQJFlqc3
Vr7q+PwwKejeH83BzE0jKW3l95no6H0M3Ng5trzS7aooD/24xe6lzRc1NnHJ3/mXVk9BvPu1H6yP
KkR5sV2iISL9klJn+YmoLOcr92mg/WfSE3bvaDYnjEGiunSNh+nZlBcRZVUA
-----END CERTIFICATE REQUEST-----`),
		},
		{
			hasSubject: true,
			gns: GeneralNames{
				OtherNames: []OtherName{
					{
						TypeID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
						Value: generateOtherName(t, UniversalValue{
							Utf8String: "upn@domain.test",
						}),
					},
				},
				RFC822Names: []string{"email@domain.test"},
			},
			sanExtension: extractSANsFromCertificateRequest(t, `
generated with: openssl req -nodes -newkey rsa:2048 -subj "/CN=someCN" \
 -addext 'subjectAltName=otherName:msUPN;UTF8:upn@domain.test,email:email@domain.test
-----BEGIN CERTIFICATE REQUEST-----
MIICpjCCAY4CAQAwETEPMA0GA1UEAwwGc29tZUNOMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAv/K6rYe4eJWc0lpmfkyDPdYHiEr3FdQYrLVjhUKEnczh
kh2sSTB/KxgrnM5q2lBdYtD9DC8kDtkRXPPaoUNBaG04ajOhbNkixrjniQj/gyE9
Pi2+jTy+rhx+4LD9Rbkwr9LHi43ttU6BHH7D+q0IqLYwD+Q0Of/Dc3VOGRKWdNl2
3aRAaVzovqtkTlhX2Awq32VjEoQcbuZNZYwdE42DkmoCWVkA7BWsDxZRSkW5tDXp
eQM3oey09v4rC9mA9KyScxglnMT3L1qAxwv3TCpMVxRY+OEKuoygBvvYtRUxPUk9
UxQwS+SlFHsx7FSFsFA3ESL3Dqz7e/2vSYwycIm1zwIDAQABoFAwTgYJKoZIhvcN
AQkOMUEwPzA9BgNVHREENjA0oB8GCisGAQQBgjcUAgOgEQwPdXBuQGRvbWFpbi50
ZXN0gRFlbWFpbEBkb21haW4udGVzdDANBgkqhkiG9w0BAQsFAAOCAQEARLAtGEsP
biMKMpSVHfBXHYG4isu3UvKmI14shGxF2flwqgFRxSUzsJ+URnT69po2fcQWwGoo
yrq3LHkJgSFQblzLLWHk7lBB8QpSMc4r5doGBMnSJfMuXCsXvspEWfgE3zvwizyl
yU5Rw5tB6tWG6M7/XGL/n2cb9Po9GXlBI3J/ll8aVQtxRP2XvAT6M9PBOctgKfv3
FErFrvGWmrnhuGhQYcpXUv+ROLEd7b6vfocUKf8rSFbY5kot4mckmgeSmzt1nhyF
sYxhnyLtZp8LVvT28a66jPz1QBCMkPrqkeXf276ySvw4Dfb6HPkT5EFVwy4XPlU8
Im17c/85tkZPEA==
-----END CERTIFICATE REQUEST-----
`),
		},
		{
			hasSubject: true,
			gns: GeneralNames{
				OtherNames: []OtherName{
					{
						TypeID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2},
						Value: generateOtherName(t, UniversalValue{
							Bytes: []byte{
								0x30, 0x2f, 0xa0, 0x10, 0x1b, 0xe, 0x59, 0x4f,
								0x55, 0x52, 0x5f, 0x52, 0x45, 0x41, 0x4c, 0x4d,
								0x4e, 0x41, 0x4d, 0x45, 0xa1, 0x1b, 0x30, 0x19,
								0xa0, 0x3, 0x2, 0x1, 0x1, 0xa1, 0x12, 0x30, 0x10,
								0x1b, 0xe, 0x59, 0x4f, 0x55, 0x52, 0x5f, 0x50,
								0x52, 0x49, 0x4e, 0x43, 0x4e, 0x41, 0x4d, 0x45,
							},
						}),
					},
				},
			},
			sanExtension: extractSANsFromCertificate(t, `-----BEGIN CERTIFICATE-----
MIID2zCCAsOgAwIBAgIUKGdEqu7o6HfNYvNzRMqA5MFvuK4wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzEwMzExMDExMzJaFw0yNDEw
MzAxMDExMzJaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCjuph5kaTvvd2xJ0HYFWrxjcLyISQCkucqIVP1YLTB
vvK+SwrXjGAOyPYUnL8NTTrIPGUuuMik8xKdYS2Fbn57Pse8TateYIB7y3tiPi1O
KEkEB16wam+HpqG8U273lAl8C2chwEnR7MnaYrOmiDK6j8uUgaeEDa7lAth05xNt
bkknPzT6xy30PC4wvhg55RsRdAJON1CVEKa/DzIHpgKEuSnIBV75NavIq9NF6MYd
RquvY6bPXRK0Yy/A/I4qwrnSKTW2aPJewRmXWKQnps+ohS9+ZCTme3+2cjJwL6dq
91qVZbPBgrU5v+CXD9+VteYFNyxYPrqR22hjI7taeKGnAgMBAAGjgcIwgb8wCQYD
VR0TBAIwADALBgNVHQ8EBAMCA6gwEgYDVR0lBAswCQYHKwYBBQIDBDAdBgNVHQ4E
FgQUbL4ZtZgpxz/nZDFv0d1Qhot3GFQwHwYDVR0jBBgwFoAUPRnKJ8PE+qJx95jJ
x7px6H6A53AwCQYDVR0SBAIwADBGBgNVHREEPzA9oDsGBisGAQUCAqAxMC+gEBsO
WU9VUl9SRUFMTU5BTUWhGzAZoAMCAQGhEjAQGw5ZT1VSX1BSSU5DTkFNRTANBgkq
hkiG9w0BAQsFAAOCAQEAU9Xlhsh8tp8psdyeQj3YcFgR/4dpy+TmIUToP+deukUQ
cpzev6e+tMtBwWwVJFuY3d5SVQBhrMF1x4/CmusCA6JuDrYKaCJGPuURvSaZ/CNb
fWuE/tdh1DxR20x4JruTiDpy3tVswAnOWKv6TWCqmdo9HydnLVx+7nXcbyzbZ8lX
U8GrBNFMcOI3rpYTeQWjzSbr2gGeM59CVlPqgLbG2WcN6bBSJDfiPk6rPGthzfph
jsDo7Ui1glzZOaHat9f17nMxpgTM8l+oqexvcUnZ+Cfr+FBRWkRNLsxBdOOPoBqY
wWy44hfcegrvch51oNMscwQ5NCJRGYI6q3T9yexVug==
-----END CERTIFICATE-----`),
		},
	}

	for _, tc := range testcases {
		{
			extension, err := MarshalSANs(tc.gns, tc.hasSubject)
			if err != nil {
				t.Errorf("MarshalSANs returned an error: %v", err)
			}

			if !reflect.DeepEqual(extension, tc.sanExtension) {
				t.Errorf("Expected extension: %v, got: %v", tc.sanExtension, extension)
			}
		}

		{
			gns, err := UnmarshalSANs(tc.sanExtension.Value)
			if err != nil {
				t.Errorf("UnmarshalSANs returned an error: %v", err)
			}

			if !reflect.DeepEqual(gns, tc.gns) {
				t.Errorf("Expected GeneralNames: %v, got: %v", tc.gns, gns)
			}
		}
	}
}
