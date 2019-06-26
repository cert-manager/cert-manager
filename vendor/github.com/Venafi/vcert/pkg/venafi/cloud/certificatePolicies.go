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
	"regexp"
	"strings"
	"time"
)

type certificateTemplate struct {
	ID                                  string `json:"id,omitempty"`
	CompanyID                           string `json:"companyId,omitempty"`
	CertificateAuthority                string `json:"certificateAuthority"`
	Name                                string `json:"name,omitempty"`
	CertificateAuthorityAccountId       string `json:"certificateAuthorityAccountId"`
	CertificateAuthorityProductOptionId string `json:"certificateAuthorityProductOptionId"`
	Product                             struct {
		CertificateAuthority string `json:"certificateAuthority"`
		ProductName          string `json:"productName"`
	} `json:"product"`
	Priority               int              `json:"priority"`
	SystemGenerated        bool             `json:"systemGenerated,omitempty"`
	CreationDateString     string           `json:"creationDate,omitempty"`
	CreationDate           time.Time        `json:"-"`
	ModificationDateString string           `json:"modificationDate"`
	ModificationDate       time.Time        `json:"-"`
	Status                 string           `json:"status"`
	Reason                 string           `json:"reason"`
	SubjectCNRegexes       []string         `json:"subjectCNRegexes,omitempty"`
	SubjectORegexes        []string         `json:"subjectORegexes,omitempty"`
	SubjectOURegexes       []string         `json:"subjectOURegexes,omitempty"`
	SubjectSTRegexes       []string         `json:"subjectSTRegexes,omitempty"`
	SubjectLRegexes        []string         `json:"subjectLRegexes,omitempty"`
	SubjectCValues         []string         `json:"subjectCValues,omitempty"`
	SANRegexes             []string         `json:"sanRegexes,omitempty"`
	KeyTypes               []allowedKeyType `json:"keyTypes,omitempty"`
	KeyReuse               bool             `json:"keyReuse,omitempty"`
}
type allowedKeyType struct {
	KeyType    keyType
	KeyLengths []int
}

type keyType string

func (ct certificateTemplate) toPolicy() (p endpoint.Policy) {
	addStartEnd := func(s string) string {
		if !strings.HasPrefix(s, "^") {
			s = "^" + s
		}
		if !strings.HasSuffix(s, "$") {
			s = s + "$"
		}
		return s
	}
	addStartEndToArray := func(ss []string) []string {
		a := make([]string, len(ss))
		for i, s := range ss {
			a[i] = addStartEnd(s)
		}
		return a
	}
	if len(ct.SubjectCValues) == 0 {
		ct.SubjectCValues = []string{".*"}
	}
	p.SubjectCNRegexes = addStartEndToArray(ct.SubjectCNRegexes)
	p.SubjectOURegexes = addStartEndToArray(ct.SubjectOURegexes)
	p.SubjectCRegexes = addStartEndToArray(ct.SubjectCValues)
	p.SubjectSTRegexes = addStartEndToArray(ct.SubjectSTRegexes)
	p.SubjectLRegexes = addStartEndToArray(ct.SubjectLRegexes)
	p.SubjectORegexes = addStartEndToArray(ct.SubjectORegexes)
	p.DnsSanRegExs = addStartEndToArray(ct.SANRegexes)
	p.AllowKeyReuse = ct.KeyReuse
	allowWildCards := false
	for _, s := range p.SubjectCNRegexes {
		if strings.HasPrefix(s, "^.*") {
			allowWildCards = true
		}
	}
	if !allowWildCards {
		for _, s := range p.DnsSanRegExs {
			if strings.HasPrefix(s, "^.*") {
				allowWildCards = true
			}
		}
	}
	p.AllowWildcards = allowWildCards
	for _, kt := range ct.KeyTypes {
		keyConfiguration := endpoint.AllowedKeyConfiguration{}
		if err := keyConfiguration.KeyType.Set(string(kt.KeyType)); err != nil {
			panic(err)
		}
		keyConfiguration.KeySizes = kt.KeyLengths[:]
		p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, keyConfiguration)
	}
	return
}

func isNotRegexp(s string) bool {
	matched, err := regexp.MatchString(`[a-zA-Z0-9 ]+`, s)
	if !matched || err != nil {
		return false
	}
	return true
}
func (ct certificateTemplate) toZoneConfig(zc *endpoint.ZoneConfiguration) {
	if len(ct.SubjectCValues) > 0 && isNotRegexp(ct.SubjectCValues[0]) {
		zc.Country = ct.SubjectCValues[0]
	}
	if len(ct.SubjectORegexes) > 0 && isNotRegexp(ct.SubjectORegexes[0]) {
		zc.Organization = ct.SubjectORegexes[0]
	}
	if len(ct.SubjectSTRegexes) > 0 && isNotRegexp(ct.SubjectSTRegexes[0]) {
		zc.Province = ct.SubjectSTRegexes[0]
	}
	if len(ct.SubjectLRegexes) > 0 && isNotRegexp(ct.SubjectLRegexes[0]) {
		zc.Locality = ct.SubjectLRegexes[0]
	}
	for _, ou := range ct.SubjectOURegexes {
		if isNotRegexp(ou) {
			zc.OrganizationalUnit = append(zc.OrganizationalUnit, ou)
		}
	}
}

/*
"signatureAlgorithm":{"type":"string","enum":["MD2_WITH_RSA_ENCRYPTION","MD5_WITH_RSA_ENCRYPTION","SHA1_WITH_RSA_ENCRYPTION","SHA1_WITH_RSA_ENCRYPTION2","SHA256_WITH_RSA_ENCRYPTION","SHA384_WITH_RSA_ENCRYPTION","SHA512_WITH_RSA_ENCRYPTION","ID_DSA_WITH_SHA1","dsaWithSHA1","EC_DSA_WITH_SHA1","EC_DSA_WITH_SHA224","EC_DSA_WITH_SHA256","EC_DSA_WITH_SHA384","EC_DSA_WITH_SHA512","UNKNOWN","SHA1_WITH_RSAandMGF1","GOST_R3411_94_WITH_GOST_R3410_2001","GOST_R3411_94_WITH_GOST_R3410_94"]},
"signatureHashAlgorithm":{"type":"string","enum":["MD5","SHA1","MD2","SHA224","SHA256","SHA384","SHA512","UNKNOWN","GOSTR3411_94"]}
*/
