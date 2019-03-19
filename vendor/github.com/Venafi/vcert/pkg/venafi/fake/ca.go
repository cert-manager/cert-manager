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

package fake

import (
	"crypto/x509"
	"encoding/pem"
)

const caCertPEM = `-----BEGIN CERTIFICATE-----
MIID1TCCAr2gAwIBAgIJAIOVTvMIMD7OMA0GCSqGSIb3DQEBCwUAMIGAMQswCQYD
VQQGEwJVUzENMAsGA1UECAwEVXRhaDEXMBUGA1UEBwwOU2FsdCBMYWtlIENpdHkx
DzANBgNVBAoMBlZlbmFmaTEbMBkGA1UECwwSTk9UIEZPUiBQUk9EVUNUSU9OMRsw
GQYDVQQDDBJWQ2VydCBUZXN0IE1vZGUgQ0EwHhcNMTgwMzI3MTAyNTI5WhcNMzgw
MzIyMTAyNTI5WjCBgDELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxFzAVBgNV
BAcMDlNhbHQgTGFrZSBDaXR5MQ8wDQYDVQQKDAZWZW5hZmkxGzAZBgNVBAsMEk5P
VCBGT1IgUFJPRFVDVElPTjEbMBkGA1UEAwwSVkNlcnQgVGVzdCBNb2RlIENBMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0BobDKthxG5SuMfAp2heyDQN
/IL9NTEnFJUUl/CkLEQTSQT68M9US7TCxi+FOizIoev2k4Nkovgk7uM0q94aygbh
cHyTTL64uphHwcClu99ZQ6DIwzDH2gREsLWfj+KXw4bPsne+5tGxv2+0jG2at5or
p/nOQWYD1C1HB6ZQqvP3PypDjou7Uh+Y00bOfXkbYWr8GkX4XAL6UtC0jUnsBEZX
CuwO1BlIIoKNokhOV7Jcb3l/jurjzVWfem+tqwYb/Tkj6MI1YBqt6Yy2EsGsoAv1
E5/IGcjSQnLEqDWhpY0s2fA4o+bAMzyakDFKJoQbF982QhS2fT+d87vQlnMi1QID
AQABo1AwTjAdBgNVHQ4EFgQUzqRFDvLX0mz4AjPb45tLGavm8AcwHwYDVR0jBBgw
FoAUzqRFDvLX0mz4AjPb45tLGavm8AcwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAWbRgS1qUyGMh3ToJ060s5cdoKzyx/ji5pRPXRxrmzzSxP+dlKX7h
AKUgYOV9FU/k2f4C7TeCZSsir20x8fKRg4qs6r8vHTcWnkC6A08SNlT5kjyJl8vt
qQTEsemnyBFis8ZFUfYdmNYqZXuWSb7ZBfNkR7qMVna8A87NyEmTtlTBkZYSTOaB
NRuOli+/6akXg/OW/GfVUD11D413CtZsWNzKaxj1WH88mjBYwQx2pGRzMWHfWBka
f6ZUnA9hhqxO4CHqQWmKPHftbGscwx5yg/J6J7TfG+rYd5ZVVhrr2un2xpOTctjO
lriDCQa4FOwP9/x1OJRXEsSl5YFqBppX5A==
-----END CERTIFICATE-----`

const caKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0BobDKthxG5SuMfAp2heyDQN/IL9NTEnFJUUl/CkLEQTSQT6
8M9US7TCxi+FOizIoev2k4Nkovgk7uM0q94aygbhcHyTTL64uphHwcClu99ZQ6DI
wzDH2gREsLWfj+KXw4bPsne+5tGxv2+0jG2at5orp/nOQWYD1C1HB6ZQqvP3PypD
jou7Uh+Y00bOfXkbYWr8GkX4XAL6UtC0jUnsBEZXCuwO1BlIIoKNokhOV7Jcb3l/
jurjzVWfem+tqwYb/Tkj6MI1YBqt6Yy2EsGsoAv1E5/IGcjSQnLEqDWhpY0s2fA4
o+bAMzyakDFKJoQbF982QhS2fT+d87vQlnMi1QIDAQABAoIBACDBuzhHUeBlrUfA
yaaQWzsQVpNE2y6gShKHVPKFwpHlNVPtIML/H7m6/l3L5SC/I+W5Cts1d4XfoZCo
2wWitHzQkHPwaA9Qhit5BPKOrIfiJF7s1C1FZHAA8/8M180CUflJIzBogPg8Ucpc
fwMLzarQ7cZHIBxTPo8LgX7GwzPlYn/kSlys8w5+gfXCbPIqWHdHgJPIm52ePLZt
0XfTF3Q+HSKzKHpdP/9kJJ3eknM/uEgyOKVPHdkq6U4HeJQq9lmp85X58cyHZOYT
qeLIqgq63x+K3Rgc2EUEOHEbdoEU9aP2fsk9M4AOHf7CpPg7htwN/5m0l4dYpIb+
tcxH+BECgYEA5u9Mtt67y37IIzwQxh80vVZ47LnZMmxKA3AOJOj3Q/fkt36TM+rM
vRFKf6dR6Yolt7JtB6bGrLyGFFbmVDtfDjt9uvseKtG4PUrwjr+ayxICsPPidPlU
hUYh2uu4+m/DK8BGV+PR6/5kwQ2cDF5pdFHECX4VY0uvBnsif1IcBDsCgYEA5rBh
HeKNiUzmfIhP345tZaVM/SFDmAWDs5GZXpCnpMoI2QBg6nU3o6ssPflLjcDjnBrK
VpDlGsTBldX+HhXuEFJzUFASbXXWPqdUyMPzcTQuJWRH+s7Pz94gu/FliNJwmYu2
tsS/PuId4O7dA/Bkhp94sH7OW4iD451xyn4RVC8CgYBtlLu4QrSl+UEKxyPGf2RN
O80ht4aC0LPGMdPkW8+JJwYWtC8xgYcpaB0Lud+6i90d78Kg0NiRetu8pwegjJOs
czpUEXjdJKriGr9PXUgceC1ivjeE/hLHMuI5uYULASGBjzlR1z7zVsGEgeq8S8iK
c4osXvHTLkSdNKzH8bRtpQKBgQDkOZlLHKjULi1VBPKohFr8lcYOJAugacw7Kg+m
u8vvPyXzsekv69mo5Z72jR1PV4aXGPYXIHBYxFGU8Eng7+c/ZKLK0Pz6J/tWrus1
WI8O7wW8XnLL0jFMQED4T0EZVMCrV8rjFNDz4HaY4xfrXrfFbB3V1w5HBk8dL9W0
9HYmZwKBgQCN6xAb82gwFM0H1w4iu6MnA2LyLc/19xn8khgNynW3cUznvyKGQuQo
ZEU0fw9VRRyQVwUwjAaLbIuME4cKhGjcJUvGPLftNamTlFS/TvtE1fwauGBXYc5o
wWh1aVElz5xMF+SnGUCW7t02dvhK0i29mOfx/eG5jkSm33NvVBq/IA==
-----END RSA PRIVATE KEY-----`

var (
	caBlock, _ = pem.Decode([]byte(caCertPEM))
	caCrt, _   = x509.ParseCertificate(caBlock.Bytes)

	caKeyBlock, _ = pem.Decode([]byte(caKeyPEM))
	caKey, _      = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
)
