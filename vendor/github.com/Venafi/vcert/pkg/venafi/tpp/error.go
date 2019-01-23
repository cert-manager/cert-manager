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

package tpp

import (
	"encoding/json"
	"fmt"
)

type responseError struct {
	ErrorDetails string `json:"ErrorDetails,omitempty"`
}

func NewResponseError(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("failed to parser empty error message")
	}
	var data = &responseError{}
	err := json.Unmarshal(b, data)
	if err != nil {
		return fmt.Errorf("failed to parser server error: %s", err)
	}
	return data
}

func (e *responseError) Error() string {
	return e.ErrorDetails
}
