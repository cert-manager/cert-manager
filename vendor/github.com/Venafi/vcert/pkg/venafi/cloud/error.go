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
	"fmt"
)

type responseError struct {
	Code    int         `json:"code,omitempty"`
	Message string      `json:"message,omitempty"`
	Args    interface{} `json:"args,omitempty"`
}

type jsonData struct {
	Errors []responseError `json:"errors,omitempty"`
}

func parseResponseErrors(b []byte) ([]responseError, error) {
	var data jsonData
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, err
	}

	return data.Errors, nil
}

func parseResponseError(b []byte) (responseError, error) {
	e := responseError{}
	err := json.Unmarshal(b, &e)
	if err != nil {
		return e, err
	}

	return e, nil
}

func (re *responseError) parseResponseArgs() (string, error) {
	if re.Args == nil {
		return "", nil
	}
	return fmt.Sprintf("%v", re.Args), nil
}
