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

package cloud

import (
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"time"
)

type company struct {
	ID                 string    `json:"id,omitempty"`
	Name               string    `json:"name,omitempty"`
	CompanyType        string    `json:"companyType,omitempty"`
	Active             bool      `json:"active,omitempty"`
	CreationDateString string    `json:"creationDate,omitempty"`
	CreationDate       time.Time `json:"-"`
	Domains            []string  `json:"domains,omitempty"`
}

type zone struct {
	ID                               string              `json:"id,omitempty"`
	CompanyID                        string              `json:"companyId,omitempty"`
	Tag                              string              `json:"tag,omitempty"`
	ZoneType                         string              `json:"zoneType,omitempty"`
	CertificatePolicyIDs             certificatePolicyID `json:"certificatePolicyIds,omitempty"`
	DefaultCertificateIdentityPolicy string              `json:"defaultCertificateIdentityPolicyId,omitempty"`
	DefaultCertificateUsePolicy      string              `json:"defaultCertificateUsePolicyId,omitempty"`
	SystemGenerated                  bool                `json:"systemGeneratedate,omitempty"`
	CreationDateString               string              `json:"creationDate,omitempty"`
	CreationDate                     time.Time           `json:"-"`
}

type certificatePolicyID struct {
	CertificateIdentity []string `json:"CERTIFICATE_IDENTITY,omitempty"`
	CertificateUse      []string `json:"CERTIFICATE_USE,omitempty"`
}

func (z *zone) GetZoneConfiguration(ud *userDetails, policy *certificatePolicy) *endpoint.ZoneConfiguration {
	zoneConfig := endpoint.ZoneConfiguration{}

	if policy != nil {
		if policy.KeyTypes != nil {
			certKeyType := certificate.KeyTypeRSA
			for _, kt := range policy.KeyTypes {
				certKeyType.Set(fmt.Sprintf("%s", kt.KeyType))
				keyConfiguration := endpoint.AllowedKeyConfiguration{}
				keyConfiguration.KeyType = certKeyType
				for _, size := range kt.KeyLengths {
					keyConfiguration.KeySizes = append(keyConfiguration.KeySizes, size)
				}
				zoneConfig.AllowedKeyConfigurations = append(zoneConfig.AllowedKeyConfigurations, keyConfiguration)
			}
		}
	}
	return &zoneConfig
}

const (
	zoneKeyGeneratorDeviceKeyGeneration  = "DEVICE_KEY_GENERATION"
	zoneKeyGeneratorCentralKeyGeneration = "CENTRAL_KEY_GENERATION"
	zoneKeyGeneratorUnknown              = "UNKNOWN"
)

const (
	zoneEncryptionTypeRSA        = "RSA"
	zoneEncryptionTypeDSA        = "DSA"
	zoneEncryptionTypeEC         = "EC"
	zoneEncryptionTypeGOST3410   = "GOST3410"
	zoneEncryptionTypeECGOST3410 = "ECGOST3410"
	zoneEncryptionTypeRESERVED3  = "RESERVED3"
	zoneEncryptionTypeUnknown    = "UNKNOWN"
)

const (
	zoneHashAlgorithmMD5         = "MD5"
	zoneHashAlgorithmSHA1        = "SHA1"
	zoneHashAlgorithmMD2         = "MD2"
	zoneHashAlgorithmSHA224      = "SHA224"
	zoneHashAlgorithmSHA256      = "SHA256"
	zoneHashAlgorithmSHA384      = "SHA384"
	zoneHashAlgorithmSHA512      = "SHA512"
	zoneHashAlgorithmUnknown     = "UNKNOWN"
	zoneHashAlgorithmGOSTR341194 = "GOSTR3411_94"
)

const (
	zoneValidityPeriodLTE90 = "LTE_90_DAYS"
	zoneValidityPeriodGT90  = "GT_90_DAYS"
	zoneValidityPeriodOther = "OTHER"
)

const (
	zoneCertificateAuthorityTypeCondorTest = "CONDOR_TEST_CA"
	zoneCertificateAuthorityTypePublic     = "PUBLIC_CA"
	zoneCertificateAuthorityTypePrivate    = "PRIVATE_CA"
	zoneCertificateAuthorityTypeOther      = "OTHER"
)
