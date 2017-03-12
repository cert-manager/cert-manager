package secret

import (
	"testing"

	"github.com/stretchr/testify/assert"
	api "k8s.io/client-go/pkg/api/v1"
)

var exampleCert = `-----BEGIN CERTIFICATE-----
MIIFJTCCBA2gAwIBAgISAz7Pd81CSjgJA3tximo5pYiDMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNjA0MjcxMDUyMDBaFw0x
NjA3MjYxMDUyMDBaMCAxHjAcBgNVBAMTFWVjaG8xMjMua3ViZS5zd2luZS5kZTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANpxdM9hmcpemu3ZYejK+oPj
iBeXJT1p4LzKNgSr7on5x9xp7mIVJ+aMjbE657gHvZB699fFn+c09AcNkZd2Yo6k
peKDcjKzGyAh4Kxb5FQeiTwfhgoGHat8J4Wn71k2Tdw+90Bmq21QxBwb6BNRyOis
9+2t1jdiB5juBFcJmm87NNAjOJayxwG8PT7+q1DU0lRKIPzq8rFPeFhgBHpu6Hjp
O3Txie6wI4u8i0PAcyzIAeFcAj5PveIHVYU5MffyJbkyUMm50+h1zxVgQ8EazpAD
o66oQ369Xx28qCNJ110HuYSwtPQ0NvRNeXRKZoylD1JGolTqR4PccwR8fShXkm8C
AwEAAaOCAi0wggIpMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUbj56pfzVJZ7ERm3b
DHUiVrZCEswwHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwcAYIKwYB
BQUHAQEEZDBiMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5pbnQteDMubGV0c2Vu
Y3J5cHQub3JnLzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNl
bmNyeXB0Lm9yZy8wNwYDVR0RBDAwLoIVZWNobzEyMy5rdWJlLnN3aW5lLmRlghVl
Y2hvNDU2Lmt1YmUuc3dpbmUuZGUwgf4GA1UdIASB9jCB8zAIBgZngQwBAgEwgeYG
CysGAQQBgt8TAQEBMIHWMCYGCCsGAQUFBwIBFhpodHRwOi8vY3BzLmxldHNlbmNy
eXB0Lm9yZzCBqwYIKwYBBQUHAgIwgZ4MgZtUaGlzIENlcnRpZmljYXRlIG1heSBv
bmx5IGJlIHJlbGllZCB1cG9uIGJ5IFJlbHlpbmcgUGFydGllcyBhbmQgb25seSBp
biBhY2NvcmRhbmNlIHdpdGggdGhlIENlcnRpZmljYXRlIFBvbGljeSBmb3VuZCBh
dCBodHRwczovL2xldHNlbmNyeXB0Lm9yZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
AQsFAAOCAQEAEtoklts9Lof0zHkeVsAahQ80vd1r4HnWKUzt5ai8zt33MZiN4vgu
hSzja83XRSfegPolV1zUZz00pwjFvOCsXt0a1ijeIYzuLs4loSBshi/rbN8T5nZo
cEKbPm0CU6X6fespcOD+wLEre7+nENap2rVVAdZa/zrGPx5+gxaESKdYW493py2W
kIiaCTmFeNZae2GFly6DDF+znSjLb5FHFFM1tEtG3REG8g/VvJae6oB78+9mDY97
XbTj5kDbPrE4lnUgBTejAHSXLJHPBON9upyunPAX0VLZwTJAtfFSbpqSXLdAo1U9
DmMX4zJtIg37+iifSd9KMNxvHbkrS08XKw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
`

func TestSecret_TlsDomains(t *testing.T) {
	s := &Secret{
		SecretApi: &api.Secret{
			Data: map[string][]byte{
				api.TLSCertKey: []byte(exampleCert),
			},
		},
	}

	domains, err := s.TlsDomains()

	assert.Nil(t, err)
	assert.EqualValues(
		t,
		[]string{"echo123.kube.swine.de", "echo456.kube.swine.de"},
		domains,
	)

	assert.True(t, s.TlsDomainsInclude([]string{"echo123.kube.swine.de"}))
	assert.True(t, s.TlsDomainsInclude([]string{"echo456.kube.swine.de"}))
	assert.True(t, s.TlsDomainsInclude([]string{"echo123.kube.swine.de", "echo456.kube.swine.de"}))
	assert.True(t, s.TlsDomainsInclude([]string{}))
	assert.False(t, s.TlsDomainsInclude([]string{"google.de"}))
	assert.False(t, s.TlsDomainsInclude([]string{"echo123.kube.swine.de", "echo456.kube.swine.de", "echo789.kube.swine.de"}))

}

func TestSecret_TlsExpireTime(t *testing.T) {
	s := &Secret{
		SecretApi: &api.Secret{
			Data: map[string][]byte{
				api.TLSCertKey: []byte(exampleCert),
			},
		},
	}

	expireTime, err := s.TlsExpireTime()

	assert.Nil(t, err)
	assert.EqualValues(t, 1469530320, expireTime.Unix())
}
