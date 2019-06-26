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
	ID                           string    `json:"id,omitempty"`
	CompanyID                    string    `json:"companyId,omitempty"`
	Tag                          string    `json:"tag,omitempty"`
	ZoneType                     string    `json:"zoneType,omitempty"`
	SystemGenerated              bool      `json:"systemGenerated,omitempty"`
	CreationDateString           string    `json:"creationDate,omitempty"`
	CreationDate                 time.Time `json:"-"`
	CertificateIssuingTemplateId string    `json:"certificateIssuingTemplateId"`
}

func (z *zone) getZoneConfiguration(ud *userDetails, policy *certificateTemplate) (zoneConfig *endpoint.ZoneConfiguration) {
	zoneConfig = endpoint.NewZoneConfiguration()
	if policy == nil {
		return
	}
	zoneConfig.Policy = policy.toPolicy()
	policy.toZoneConfig(zoneConfig)
	return
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
