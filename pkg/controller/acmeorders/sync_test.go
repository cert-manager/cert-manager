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

package acmeorders

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	acmeapi "golang.org/x/crypto/acme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"
	fakeclock "k8s.io/utils/clock/testing"

	accountstest "github.com/cert-manager/cert-manager/pkg/acme/accounts/test"
	acmecl "github.com/cert-manager/cert-manager/pkg/acme/client"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	schedulertest "github.com/cert-manager/cert-manager/pkg/scheduler/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestSync(t *testing.T) {
	nowTime := time.Now()
	nowMetaTime := metav1.NewTime(nowTime)
	fixedClock := fakeclock.NewFakeClock(nowTime)

	testIssuerHTTP01 := gen.Issuer("testissuer", gen.SetIssuerACME(cmacme.ACMEIssuer{
		Solvers: []cmacme.ACMEChallengeSolver{
			{
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
				},
			},
		},
	}))

	testIssuerHTTP01TestCom := gen.Issuer("testissuer", gen.SetIssuerACME(cmacme.ACMEIssuer{
		Solvers: []cmacme.ACMEChallengeSolver{
			{
				Selector: &cmacme.CertificateDNSNameSelector{
					DNSNames: []string{"test.com"},
				},
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
				},
			},
		},
	}))

	testIssuerHTTP01TestComPreferredChain := gen.Issuer("testissuer", gen.SetIssuerACME(cmacme.ACMEIssuer{
		PreferredChain: "DST Root CA X3", // This is the common name of the root certificate in the testAltCert
		Solvers: []cmacme.ACMEChallengeSolver{
			{
				Selector: &cmacme.CertificateDNSNameSelector{
					DNSNames: []string{"test.com"},
				},
				HTTP01: &cmacme.ACMEChallengeSolverHTTP01{
					Ingress: &cmacme.ACMEChallengeSolverHTTP01Ingress{},
				},
			},
		},
	}))

	testOrder := gen.Order("testorder",
		gen.SetOrderCommonName("test.com"),
		gen.SetOrderIssuer(cmmeta.ObjectReference{
			Name: testIssuerHTTP01TestCom.Name,
		}),
	)

	testOrderIP := gen.Order("testorder", gen.SetOrderIssuer(cmmeta.ObjectReference{Name: testIssuerHTTP01.Name}), gen.SetOrderIPAddresses("10.0.0.1"))

	pendingStatus := cmacme.OrderStatus{
		State:       cmacme.Pending,
		URL:         "http://testurl.com/abcde",
		FinalizeURL: "http://testurl.com/abcde/finalize",
		Authorizations: []cmacme.ACMEAuthorization{
			{
				URL:        "http://authzurl",
				Identifier: "test.com",
				Challenges: []cmacme.ACMEChallenge{
					{
						URL:   "http://chalurl",
						Token: "token",
						Type:  "http-01",
					},
				},
			},
		},
	}

	erroredStatus := cmacme.OrderStatus{
		State: cmacme.Errored,
	}

	erroredStatusWithDetail := cmacme.OrderStatus{
		State:       cmacme.Errored,
		FailureTime: &nowMetaTime,
		URL:         "http://testurl.com/abcde",
		FinalizeURL: "http://testurl.com/abcde/finalize",
		Reason:      "Failed to finalize Order: 429 : some error",
		Authorizations: []cmacme.ACMEAuthorization{
			{
				URL:          "http://authzurl",
				Identifier:   "test.com",
				InitialState: cmacme.Valid,
				Challenges: []cmacme.ACMEChallenge{
					{
						URL:   "http://chalurl",
						Token: "token",
						Type:  "http-01",
					},
				},
			},
		},
	}

	acmeError429 := acmeapi.Error{
		StatusCode: 429,
		Detail:     "some error",
	}
	acmeError403 := acmeapi.Error{
		StatusCode: 403,
		Detail:     "some error",
	}

	// testCert is using the following Let's Encrypt chain (X1 is not included):
	//   leaf -> R3 -> ISRG Root X1
	testCert := `-----BEGIN CERTIFICATE-----
MIIEZjCCA06gAwIBAgISAx0TG3o1EufZi/OTOnR9vqt/MA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMzEyMTkxNjIwMjFaFw0yNDAzMTgxNjIwMjBaMBoxGDAWBgNVBAMT
D2NlcnQtbWFuYWdlci5pbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCRoMZW8
FQpb9R2fNhLps2Jms1e058hkiz9PzfyVZT4n0ONmV2OlnNXg7Y3F8v47yc5tq5W6
8oum8TN+Y2v3u2CjggJXMIICUzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBljJ3oq
zwwTlkvYYFNit4ol03klMB8GA1UdIwQYMBaAFBQusxe3WFbLrlAJQOYfr52LFMLG
MFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL3IzLm8ubGVuY3Iu
b3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5jci5vcmcvMF4GA1UdEQRX
MFWCD2NlcnQtbWFuYWdlci5pb4IUZG9jcy5jZXJ0LW1hbmFnZXIuaW+CF25ldGxp
ZnkuY2VydC1tYW5hZ2VyLmlvghN3d3cuY2VydC1tYW5hZ2VyLmlvMBMGA1UdIAQM
MAowCAYGZ4EMAQIBMIIBBgYKKwYBBAHWeQIEAgSB9wSB9ADyAHcASLDja9qmRzQP
5WoC+p0w6xxSActW3SyB2bu/qznYhHMAAAGMgxfC6wAABAMASDBGAiEA1Ac3K8oT
EGY509sNj0/hZ4x5Td6aA3HsElojcF0DOMwCIQDxXgjEDmg0vS4u5BHEndIecmHe
2cMTnTIRM8c9IW0ZTgB3AKLiv9Ye3i8vB6DWTm03p9xlQ7DGtS6i2reK+Jpt9RfY
AAABjIMXwyAAAAQDAEgwRgIhAI9E0vDiqkNXYqtVmQBxM1Nk6eOmeMtZSGoojfBW
IsHBAiEA4S+mvJMqrVQ78UtAT+SGJ9Mr6fb/T45rDmID0PDhuXEwDQYJKoZIhvcN
AQELBQADggEBAJuZ66ArEUG/98Aaz+xYPbpRAfNmllyk9o6exmmZWrAvTBgzCF+D
T+UN8XtOwVW4lTJGHBsXmY9mGtP4lPehGwSD26fJsHTGZYTUGHFwStHrhbu1tyKc
hQg/wgviBN0oRsPWcBqMp0jZkHDNUZPq6fmVGXWeX+sx6Cu+iC8BrdQiEzD8DtrJ
11n6zDjy3mW64D/8MNCGzESbJ9F9N5162Yd3JWHO2eA9FXvcDg6lY2lBitQECqz1
m8/A7QoPnC9uk/LvEnaqmLbZy7+yK/5+wDbW1y6AbIeo7On1UAXymn5zBTKlEkVm
Q+Rh9actCRTGKaeLO4ar2i59xZ9OnqZhx9c=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----
`

	// testCert is using the following Let's Encrypt chain (DST Root CA X3 is not included):
	//   leaf -> R3 -> ISRG Root X1 -> DST Root CA X3
	testAltCert := testCert + `-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC
ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL
wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D
LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK
4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5
bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y
sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ
Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4
FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc
SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql
PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND
TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1
c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx
+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB
ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu
b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E
U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu
MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC
5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW
9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG
WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O
he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC
Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5
-----END CERTIFICATE-----
`

	decodeAll := func(pemBytes []byte) [][]byte {
		var blocks [][]byte
		for {
			block, rest := pem.Decode(pemBytes)
			if block == nil {
				break
			}
			blocks = append(blocks, block.Bytes)
			pemBytes = rest
		}
		return blocks
	}

	rawTestCert := decodeAll([]byte(testCert))
	if _, err := pki.ParseSingleCertificateChainPEM([]byte(testCert)); err != nil {
		t.Fatalf("error parsing test certificate: %v", err)
	}

	rawTestAltCert := decodeAll([]byte(testAltCert))
	if _, err := pki.ParseSingleCertificateChainPEM([]byte(testAltCert)); err != nil {
		t.Fatalf("error parsing test certificate: %v", err)
	}

	testOrderPending := gen.OrderFrom(testOrder, gen.SetOrderStatus(pendingStatus))
	testOrderInvalid := testOrderPending.DeepCopy()
	testOrderInvalid.Status.State = cmacme.Invalid
	testOrderInvalid.Status.FailureTime = &nowMetaTime
	testOrderErrored := gen.OrderFrom(testOrder, gen.SetOrderStatus(erroredStatus))
	testOrderErrored.Status.FailureTime = &nowMetaTime
	testOrderErroredWithDetail := gen.OrderFrom(testOrderPending, gen.SetOrderStatus(erroredStatusWithDetail))
	testOrderValid := testOrderPending.DeepCopy()
	testOrderValid.Status.State = cmacme.Valid
	// pem encoded word 'test'
	testOrderValid.Status.Certificate = []byte(testCert)
	testOrderReady := testOrderPending.DeepCopy()
	testOrderReady.Status.State = cmacme.Ready

	testOrderValidAltCert := gen.OrderFrom(testOrder, gen.SetOrderStatus(pendingStatus))
	testOrderValidAltCert.Status.State = cmacme.Valid
	testOrderValidAltCert.Status.Certificate = []byte(testAltCert)

	fakeHTTP01ACMECl := &acmecl.FakeACME{
		FakeHTTP01ChallengeResponse: func(s string) (string, error) {
			// TODO: assert s = "token"
			return "key", nil
		},
	}
	testAuthorizationChallenge, err := buildPartialChallenge(context.TODO(), testIssuerHTTP01TestCom, testOrderPending, testOrderPending.Status.Authorizations[0])

	if err != nil {
		t.Fatalf("error building Challenge resource test fixture: %v", err)
	}
	key, err := fakeHTTP01ACMECl.FakeHTTP01ChallengeResponse(testAuthorizationChallenge.Spec.Token)
	if err != nil {
		t.Fatalf("error building Challenge resource test fixture: %v", err)
	}
	testAuthorizationChallenge.Spec.Key = key
	testAuthorizationChallengeValid := testAuthorizationChallenge.DeepCopy()
	testAuthorizationChallengeValid.Status.State = cmacme.Valid
	testAuthorizationChallengeInvalid := testAuthorizationChallenge.DeepCopy()
	testAuthorizationChallengeInvalid.Status.State = cmacme.Invalid

	testACMEAuthorizationPending := &acmeapi.Authorization{
		URI:    "http://authzurl",
		Status: acmeapi.StatusPending,
		Identifier: acmeapi.AuthzID{
			Value: "test.com",
		},
		Challenges: []*acmeapi.Challenge{
			{
				Type:  "http-01",
				Token: "token",
			},
		},
	}

	testACMEOrderPending := &acmeapi.Order{
		URI: testOrderPending.Status.URL,
		Identifiers: []acmeapi.AuthzID{
			{
				Type:  "dns",
				Value: "test.com",
			},
		},
		FinalizeURL: testOrderPending.Status.FinalizeURL,
		AuthzURLs:   []string{"http://authzurl"},
		Status:      acmeapi.StatusPending,
	}
	// shallow copy
	testACMEOrderValid := &acmeapi.Order{}
	*testACMEOrderValid = *testACMEOrderPending
	testACMEOrderValid.Status = acmeapi.StatusValid
	testACMEOrderValid.CertURL = "http://testurl"
	// shallow copy
	testACMEOrderReady := &acmeapi.Order{}
	*testACMEOrderReady = *testACMEOrderPending
	testACMEOrderReady.Status = acmeapi.StatusReady
	// shallow copy
	testACMEOrderInvalid := &acmeapi.Order{}
	*testACMEOrderInvalid = *testACMEOrderPending
	testACMEOrderInvalid.Status = acmeapi.StatusInvalid

	tests := map[string]testT{
		"create a new order with the acme server, set the order url on the status resource and return nil to avoid cache timing issues": {
			order: testOrder,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrder},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderPending.Namespace,
						gen.OrderFrom(testOrder, gen.SetOrderStatus(cmacme.OrderStatus{
							State:       cmacme.Pending,
							URL:         "http://testurl.com/abcde",
							FinalizeURL: "http://testurl.com/abcde/finalize",
							Authorizations: []cmacme.ACMEAuthorization{
								{
									URL: "http://authzurl",
								},
							},
						})))),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeAuthorizeOrder: func(ctx context.Context, id []acmeapi.AuthzID, opt ...acmeapi.OrderOption) (*acmeapi.Order, error) {
					return testACMEOrderPending, nil
				},
				FakeGetAuthorization: func(ctx context.Context, url string) (*acmeapi.Authorization, error) {
					if url != "http://authzurl" {
						return nil, fmt.Errorf("Invalid URL: expected http://authzurl got %q", url)
					}
					return testACMEAuthorizationPending, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"create a new order with the acme server with an IP address": {
			order: testOrderIP,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01, testOrderIP},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderPending.Namespace,
						gen.OrderFrom(testOrderIP, gen.SetOrderStatus(cmacme.OrderStatus{
							State:       cmacme.Pending,
							URL:         "http://testurl.com/abcde",
							FinalizeURL: "http://testurl.com/abcde/finalize",
							Authorizations: []cmacme.ACMEAuthorization{
								{
									URL: "http://authzurl",
								},
							},
						})))),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeAuthorizeOrder: func(ctx context.Context, id []acmeapi.AuthzID, opt ...acmeapi.OrderOption) (*acmeapi.Order, error) {
					if id[0].Value != "10.0.0.1" || id[0].Type != "ip" {
						return nil, errors.New("AuthzID needs to be the IP")
					}
					return testACMEOrderPending, nil
				},
				FakeGetAuthorization: func(ctx context.Context, url string) (*acmeapi.Authorization, error) {
					if url != "http://authzurl" {
						return nil, fmt.Errorf("Invalid URL: expected http://authzurl got %q", url)
					}
					return testACMEAuthorizationPending, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"create a challenge resource for the test.com dnsName on the order": {
			order: testOrderPending,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewCreateAction(cmacme.SchemeGroupVersion.WithResource("challenges"), testAuthorizationChallenge.Namespace, testAuthorizationChallenge)),
				},
				ExpectedEvents: []string{
					//nolint: dupword
					`Normal Created Created Challenge resource "testorder-756011405" for domain "test.com"`,
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"should refuse to create a challenge if only an unknown challenge type is offered": {
			order: gen.OrderFrom(testOrderPending, gen.SetOrderStatus(cmacme.OrderStatus{
				State:       cmacme.Pending,
				URL:         "http://testurl.com/abcde",
				FinalizeURL: "http://testurl.com/abcde/finalize",
				Authorizations: []cmacme.ACMEAuthorization{
					{
						URL:        "http://authzurl",
						Identifier: "test.com",
						Challenges: []cmacme.ACMEChallenge{
							{
								URL:   "http://chalurl",
								Token: "token",
								Type:  "unknown-type",
							},
						},
					},
				},
			})),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					testIssuerHTTP01TestCom,
				},
				ExpectedEvents: []string{
					// the 'unsupported challenge type' text is not printed here as the code that 'selects'
					// a solver to use for a challenge filters out unsupported challenge types earlier
					// in its selection routine.
					`Warning Solver Failed to determine a valid solver configuration for the set of domains on the Order: no configured challenge solvers can be used for this challenge`,
				},
			},
		},
		"skip creating a Challenge for an already valid authorization, reschedule if the ACME Order is still pending": {
			order: gen.OrderFrom(testOrder, gen.SetOrderStatus(
				cmacme.OrderStatus{
					State:       cmacme.Pending,
					URL:         "http://testurl.com/abcde",
					FinalizeURL: "http://testurl.com/abcde/finalize",
					Authorizations: []cmacme.ACMEAuthorization{
						{
							URL:          "http://authzurl",
							Identifier:   "test.com",
							InitialState: cmacme.Valid,
							Challenges: []cmacme.ACMEChallenge{
								{
									URL:   "http://chalurl",
									Token: "token",
									Type:  "http-01",
								},
							},
						},
					},
				},
			)),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending},
				ExpectedActions:    []testpkg.Action{},
				ExpectedEvents:     []string{},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(ctx context.Context, url string) (*acmeapi.Order, error) {
					return &acmeapi.Order{
						URI:         "http://testurl.com/abcde",
						Status:      acmeapi.StatusPending,
						FinalizeURL: "http://testurl.com/abcde/finalize",
						CertURL:     "",
					}, nil
				},
			},
			shouldSchedule: true,
		},
		"skip creating a Challenge for an already valid authorization": {
			order: gen.OrderFrom(testOrder, gen.SetOrderStatus(
				cmacme.OrderStatus{
					State:       cmacme.Pending,
					URL:         "http://testurl.com/abcde",
					FinalizeURL: "http://testurl.com/abcde/finalize",
					Authorizations: []cmacme.ACMEAuthorization{
						{
							URL:          "http://authzurl",
							Identifier:   "test.com",
							InitialState: cmacme.Valid,
							Challenges: []cmacme.ACMEChallenge{
								{
									URL:   "http://chalurl",
									Token: "token",
									Type:  "http-01",
								},
							},
						},
					},
				},
			)),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrder.Namespace, gen.OrderFrom(testOrder, gen.SetOrderStatus(
							cmacme.OrderStatus{
								// The 'state' field should be updated to reflect the
								// Order returned by FakeGetOrder
								State:       cmacme.Valid,
								URL:         "http://testurl.com/abcde",
								FinalizeURL: "http://testurl.com/abcde/finalize",
								Authorizations: []cmacme.ACMEAuthorization{
									{
										URL:          "http://authzurl",
										Identifier:   "test.com",
										InitialState: cmacme.Valid,
										Challenges: []cmacme.ACMEChallenge{
											{
												URL:   "http://chalurl",
												Token: "token",
												Type:  "http-01",
											},
										},
									},
								},
							},
						)),
					)),
				},
				ExpectedEvents: []string{},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(ctx context.Context, url string) (*acmeapi.Order, error) {
					return &acmeapi.Order{
						URI:         "http://testurl.com/abcde",
						Status:      acmeapi.StatusValid,
						FinalizeURL: "http://testurl.com/abcde/finalize",
						CertURL:     "",
					}, nil
				},
			},
		},
		"do nothing if the challenge for test.com is still pending": {
			order: testOrderPending,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending, testAuthorizationChallenge},
				ExpectedActions:    []testpkg.Action{},
			},
			acmeClient: &acmecl.FakeACME{
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"call GetOrder and update the order state to 'ready' if all challenges are 'valid'": {
			order: testOrderPending,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending, testAuthorizationChallengeValid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderReady.Namespace, testOrderReady)),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderReady, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"call FinalizeOrder and update the order state to 'valid' if finalize succeeds": {
			order: testOrderReady,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderReady, testAuthorizationChallengeValid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderValid.Namespace, testOrderValid)),
				},
				ExpectedEvents: []string{
					"Normal Complete Order completed successfully",
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderValid, nil
				},
				FakeCreateOrderCert: func(_ context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error) {
					return rawTestCert, testACMEOrderValid.CertURL, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"call FinalizeOrder and update the order state to 'errored' if finalize fails with a 4xx ACME error": {
			order: gen.OrderFrom(testOrderErroredWithDetail, gen.SetOrderState(cmacme.Ready)),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, gen.OrderFrom(testOrderErroredWithDetail, gen.SetOrderState(cmacme.Ready))},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderErroredWithDetail.Namespace, testOrderErroredWithDetail)),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderReady, nil
				},
				FakeCreateOrderCert: func(_ context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error) {
					return nil, "", &acmeError429
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"call FinalizeOrder, return error if finalize fails with an unspecified error": {
			order: gen.OrderFrom(testOrderErroredWithDetail, gen.SetOrderState(cmacme.Ready)),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, gen.OrderFrom(testOrderErroredWithDetail, gen.SetOrderState(cmacme.Ready))},
				ExpectedActions:    []testpkg.Action{},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderReady, nil
				},
				FakeCreateOrderCert: func(_ context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error) {
					return nil, "", errors.New("some error")
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
			expectErr: true,
		},
		"call FinalizeOrder, recover if finalize fails because order is already finalized": {
			order: testOrderReady,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderReady, testAuthorizationChallengeValid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderValid.Namespace, testOrderValid)),
				},
				ExpectedEvents: []string{
					"Normal Complete Order completed successfully",
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderValid, nil
				},
				FakeCreateOrderCert: func(_ context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error) {
					return nil, "", &acmeError403
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
				FakeFetchCert: func(_ context.Context, url string, bundle bool) ([][]byte, error) {
					if url != testACMEOrderValid.CertURL {
						return nil, errors.New("Cert URL is incorrect")
					}
					if !bundle {
						return nil, errors.New("Expecting to be called with bundle=true")
					}
					return rawTestCert, nil
				},
			},
			expectErr: false,
		},
		"call FinalizeOrder, recover if finalize fails because order is already finalized and fetch alternate cert chain": {
			order: testOrderReady,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestComPreferredChain, testOrderReady, testAuthorizationChallengeValid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderValid.Namespace, testOrderValidAltCert)),
				},
				ExpectedEvents: []string{
					"Normal Complete Order completed successfully",
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderValid, nil
				},
				FakeCreateOrderCert: func(_ context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error) {
					return nil, "", &acmeError403
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
				FakeListCertAlternates: func(_ context.Context, url string) ([]string, error) {
					if url != testACMEOrderValid.CertURL {
						return nil, errors.New("Cert URL is incorrect")
					}
					return []string{"http://alturl"}, nil
				},
				FakeFetchCert: func(_ context.Context, url string, bundle bool) ([][]byte, error) {
					if url != testACMEOrderValid.CertURL && url != "http://alturl" {
						return nil, errors.New("Cert URL is incorrect")
					}
					if !bundle {
						return nil, errors.New("Expecting to be called with bundle=true")
					}
					if url == testACMEOrderValid.CertURL {
						return rawTestCert, nil
					}
					return rawTestAltCert, nil
				},
			},
			expectErr: false,
		},
		"call FinalizeOrder fetch alternate cert chain": {
			order: testOrderReady.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestComPreferredChain, testOrderReady, testAuthorizationChallengeValid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderValid.Namespace, testOrderValidAltCert)),
				},
				ExpectedEvents: []string{
					"Normal Complete Order completed successfully",
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderValid, nil
				},
				FakeCreateOrderCert: func(_ context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error) {
					return rawTestCert, testACMEOrderValid.CertURL, nil
				},
				FakeListCertAlternates: func(_ context.Context, url string) ([]string, error) {
					if url != testACMEOrderValid.CertURL {
						return nil, errors.New("Cert URL is incorrect")
					}
					return []string{"http://alturl"}, nil

				},
				FakeFetchCert: func(_ context.Context, url string, bundle bool) ([][]byte, error) {
					if url != "http://alturl" {
						return nil, errors.New("Cert URL is incorrect: expected http://alturl got " + url)
					}
					if !bundle {
						return nil, errors.New("Expecting to be called with bundle=true")
					}
					return rawTestAltCert, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"preferred chain is default cert chain": {
			order: testOrderReady.DeepCopy(),
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{
					gen.IssuerFrom(testIssuerHTTP01TestComPreferredChain, gen.SetIssuerACMEPreferredChain("ISRG Root X1")),
					testOrderReady, testAuthorizationChallengeValid,
				},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderValid.Namespace, testOrderValid)),
				},
				ExpectedEvents: []string{
					"Normal Complete Order completed successfully",
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderValid, nil
				},
				FakeCreateOrderCert: func(_ context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error) {
					return rawTestCert, testACMEOrderValid.CertURL, nil
				},
				FakeListCertAlternates: func(_ context.Context, url string) ([]string, error) {
					return nil, errors.New("should not be called")
				},
				FakeFetchCert: func(_ context.Context, url string, bundle bool) ([][]byte, error) {
					return nil, errors.New("should not be called")
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"call GetOrder and update the order state if the challenge is 'failed'": {
			order: testOrderPending,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending, testAuthorizationChallengeInvalid},
				ExpectedActions: []testpkg.Action{
					testpkg.NewAction(coretesting.NewUpdateSubresourceAction(cmacme.SchemeGroupVersion.WithResource("orders"),
						"status",
						testOrderInvalid.Namespace, testOrderInvalid)),
				},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderInvalid, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					return "key", nil
				},
			},
		},
		"should leave the order state as-is if the challenge is marked invalid but the acme order is pending": {
			order: testOrderPending,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderPending, testAuthorizationChallengeInvalid},
				ExpectedActions:    []testpkg.Action{},
			},
			acmeClient: &acmecl.FakeACME{
				FakeGetOrder: func(_ context.Context, url string) (*acmeapi.Order, error) {
					return testACMEOrderPending, nil
				},
				FakeHTTP01ChallengeResponse: func(s string) (string, error) {
					// TODO: assert s = "token"
					return "key", nil
				},
			},
		},
		"do nothing if the order is valid": {
			order: testOrderValid,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderValid},
				ExpectedActions:    []testpkg.Action{},
			},
			acmeClient: &acmecl.FakeACME{},
		},
		"do nothing if the order is invalid": {
			order: testOrderInvalid,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderInvalid},
				ExpectedActions:    []testpkg.Action{},
			},
			acmeClient: &acmecl.FakeACME{},
		},
		"do nothing if the order is in errored state with no url or finalize url on status": {
			order: testOrderErrored,
			builder: &testpkg.Builder{
				CertManagerObjects: []runtime.Object{testIssuerHTTP01TestCom, testOrderErrored},
				ExpectedActions:    []testpkg.Action{},
			},
			acmeClient: &acmecl.FakeACME{},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// reset the fixedClock at the start of each test
			fixedClock.SetTime(nowTime)
			// always use the fixedClock unless otherwise specified
			if test.builder.Clock == nil {
				test.builder.Clock = fixedClock
			}
			runTest(t, test)
		})
	}
}

type testT struct {
	order          *cmacme.Order
	builder        *testpkg.Builder
	acmeClient     acmecl.Interface
	shouldSchedule bool
	expectErr      bool
}

func runTest(t *testing.T, test testT) {
	test.builder.T = t
	test.builder.Init()
	defer test.builder.Stop()

	cw := &controllerWrapper{}
	_, _, err := cw.Register(test.builder.Context)
	if err != nil {
		t.Errorf("Error registering the controller: %v", err)
	}

	// Set some fields on the embedded controller.
	cw.accountRegistry = &accountstest.FakeRegistry{
		GetClientFunc: func(_ string) (acmecl.Interface, error) {
			return test.acmeClient, nil
		},
	}
	gotScheduled := false
	fakeScheduler := schedulertest.FakeScheduler{
		AddFunc: func(obj types.NamespacedName, duration time.Duration) {
			gotScheduled = true
		},
	}
	cw.scheduledWorkQueue = &fakeScheduler

	test.builder.Start()

	err = cw.Sync(context.Background(), test.order)
	if err != nil && !test.expectErr {
		t.Errorf("Expected function to not error, but got: %v", err)
	}
	if err == nil && test.expectErr {
		t.Errorf("Expected function to get an error, but got: %v", err)
	}
	if gotScheduled != test.shouldSchedule {
		t.Errorf("Expected Order to be re-queued: %v got re-queued: %v", test.shouldSchedule, gotScheduled)
	}

	test.builder.CheckAndFinish(err)
}
