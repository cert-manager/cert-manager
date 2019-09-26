/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"encoding/json"
	"fmt"
	"hash/fnv"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
)

func ComputeCertificateRequestName(crt *cmapi.Certificate) (string, error) {
	crt = crt.DeepCopy()
	specBytes, err := json.Marshal(crt.Spec)
	if err != nil {
		return "", err
	}

	hashF := fnv.New32()
	_, err = hashF.Write(specBytes)
	if err != nil {
		return "", err
	}

	// shorten the cert name to 52 chars to ensure the total length of the name
	// is less than or equal to 64 characters
	return fmt.Sprintf("%.52s-%d", crt.Name, hashF.Sum32()), nil
}
