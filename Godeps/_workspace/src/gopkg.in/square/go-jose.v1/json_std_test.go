// +build std_json

/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"testing"
)

type CaseInsensitive struct {
	A int `json:"TEST"`
}

func TestCaseInsensitiveJSON(t *testing.T) {
	raw := []byte(`{"test":42}`)
	var ci CaseInsensitive
	err := UnmarshalJSON(raw, &ci)
	if err != nil {
		t.Error(err)
	}

	if ci.A != 42 {
		t.Errorf("parsing JSON should be case-insensitive (got %v)", ci)
	}
}

func TestParseCaseInsensitiveJWE(t *testing.T) {
	invalidJWE := `{"protected":"eyJlbmMiOiJYWVoiLCJBTEciOiJYWVoifQo","encrypted_key":"QUJD","iv":"QUJD","ciphertext":"QUJD","tag":"QUJD"}`
	_, err := ParseEncrypted(invalidJWE)
	if err != nil {
		t.Error("Unable to parse message with case-invalid headers", invalidJWE)
	}
}

func TestParseCaseInsensitiveJWS(t *testing.T) {
	invalidJWS := `{"PAYLOAD":"CUJD","signatures":[{"protected":"e30","signature":"CUJD"}]}`
	_, err := ParseSigned(invalidJWS)
	if err != nil {
		t.Error("Unable to parse message with case-invalid headers", invalidJWS)
	}
}

var JWKSetDuplicates = stripWhitespace(`{
     "keys": [{
         "kty": "RSA",
         "kid": "exclude-me",
         "use": "sig",
         "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT
             -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV
             wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-
             oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde
             3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC
             LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g
             HdrNP5zw",
         "e": "AQAB"
     }],
     "keys": [{
         "kty": "RSA",
         "kid": "include-me",
         "use": "sig",
         "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT
             -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV
             wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-
             oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde
             3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC
             LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g
             HdrNP5zw",
         "e": "AQAB"
     }],
     "custom": "exclude-me",
     "custom": "include-me"
   }`)

func TestDuplicateJWKSetMembersIgnored(t *testing.T) {
	type CustomSet struct {
		JsonWebKeySet
		CustomMember string `json:"custom"`
	}
	data := []byte(JWKSetDuplicates)
	var set CustomSet
	UnmarshalJSON(data, &set)
	if len(set.Keys) != 1 {
		t.Error("expected only one key in set")
	}
	if set.Keys[0].KeyID != "include-me" {
		t.Errorf("expected key with kid: \"include-me\", got: %s", set.Keys[0].KeyID)
	}
	if set.CustomMember != "include-me" {
		t.Errorf("expected custom member value: \"include-me\", got: %s", set.CustomMember)
	}
}
