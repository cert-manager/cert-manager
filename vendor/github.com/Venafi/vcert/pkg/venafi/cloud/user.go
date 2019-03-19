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
	"encoding/json"
	"time"
)

type user struct {
	Username           string    `json:"username,omitempty"`
	ID                 string    `json:"id,omitempty"`
	CompanyID          string    `json:"companyId,omitempty"`
	EmailAddress       string    `json:"emailAddress,omitempty"`
	UserType           string    `json:"userType,omitempty"`
	UserAccountType    string    `json:"userAccountType,omitempty"`
	UserStatus         string    `json:"userStatus,omitempty"`
	CreationDateString string    `json:"creationDate,omitempty"`
	CreationDate       time.Time `json:"-"`
}

type userAccount struct {
	Username           string `json:"username,omitempty"`
	Password           string `json:"password,omitempty"`
	Firstname          string `json:"firstname,omitempty"`
	Lastname           string `json:"lastname,omitempty"`
	CompanyID          string `json:"companyId,omitempty"`
	CompanyName        string `json:"companyName,omitempty"`
	UserAccountType    string `json:"userAccountType,omitempty"`
	GreCaptchaResponse string `json:"grecaptchaResponse,omitempty"`
}

func (u *user) encodeToJSON() ([]byte, error) {
	b, err := json.Marshal(u)
	return b, err
}
