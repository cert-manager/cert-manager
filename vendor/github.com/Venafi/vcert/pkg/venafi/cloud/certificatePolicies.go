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

import "time"

type certificatePolicy struct {
	CertificatePolicyType certificatePolicyType `json:"certificatePolicyType,omitempty"`
	ID                    string                `json:"id,omitempty"`
	CompanyID             string                `json:"companyId,omitempty"`
	Name                  string                `json:"name,omitempty"`
	SystemGenerated       bool                  `json:"systemGeneratedate,omitempty"`
	CreationDateString    string                `json:"creationDate,omitempty"`
	CreationDate          time.Time             `json:"-"`
	CertificateProviderID string                `json:"certificateProviderId,omitempty"`
	SubjectCNRegexes      []string              `json:"subjectCNRegexes,omitempty"`
	SubjectORegexes       []string              `json:"subjectORegexes,omitempty"`
	SubjectOURegexes      []string              `json:"subjectOURegexes,omitempty"`
	SubjectSTRegexes      []string              `json:"subjectSTRegexes,omitempty"`
	SubjectLRegexes       []string              `json:"subjectLRegexes,omitempty"`
	SubjectCRegexes       []string              `json:"subjectCRegexes,omitempty"`
	SANRegexes            []string              `json:"sanRegexes,omitempty"`
	KeyTypes              []allowedKeyType      `json:"keyTypes,omitempty"`
	KeyReuse              bool                  `json:"keyReuse,omitempty"`
}

type allowedKeyType struct {
	KeyType    keyType
	KeyLengths []int
}

type certificatePolicyType string

const (
	certificatePolicyTypeIdentity certificatePolicyType = "CERTIFICATE_IDENTITY"
	certificatePolicyTypeUse                            = "CERTIFICATE_USE"
)

type keyType string

const (
	keyTypeRSA        keyType = "RSA"
	keyTypeDSA                = "DSA"
	keyTypeEC                 = "EC"
	keyTypeGost3410           = "GOST3410"
	keyTypeECGost3410         = "ECGOST3410"
	keyTypeReserved3          = "RESERVED3"
	keyTypeUnknown            = "UNKNOWN"
)

/*
"signatureAlgorithm":{"type":"string","enum":["MD2_WITH_RSA_ENCRYPTION","MD5_WITH_RSA_ENCRYPTION","SHA1_WITH_RSA_ENCRYPTION","SHA1_WITH_RSA_ENCRYPTION2","SHA256_WITH_RSA_ENCRYPTION","SHA384_WITH_RSA_ENCRYPTION","SHA512_WITH_RSA_ENCRYPTION","ID_DSA_WITH_SHA1","dsaWithSHA1","EC_DSA_WITH_SHA1","EC_DSA_WITH_SHA224","EC_DSA_WITH_SHA256","EC_DSA_WITH_SHA384","EC_DSA_WITH_SHA512","UNKNOWN","SHA1_WITH_RSAandMGF1","GOST_R3411_94_WITH_GOST_R3410_2001","GOST_R3411_94_WITH_GOST_R3410_94"]},
"signatureHashAlgorithm":{"type":"string","enum":["MD5","SHA1","MD2","SHA224","SHA256","SHA384","SHA512","UNKNOWN","GOSTR3411_94"]}
*/
