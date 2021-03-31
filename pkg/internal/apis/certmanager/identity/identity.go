/*
Copyright 2020 The cert-manager Authors.

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

package identity

import (
	"github.com/jetstack/cert-manager/pkg/internal/api/mutation"
	"github.com/jetstack/cert-manager/pkg/internal/api/validation"
	cmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/identity/certificaterequests"
)

func AddToValidationRegistry(reg *validation.Registry) error {
	if err := reg.AddValidateFunc(&cmapi.CertificateRequest{}, certificaterequests.ValidateCreate); err != nil {
		return err
	}
	if err := reg.AddValidateUpdateFunc(&cmapi.CertificateRequest{}, certificaterequests.ValidateUpdate); err != nil {
		return err
	}

	return nil
}

func AddToMutationRegistry(reg *mutation.Registry) error {
	if err := reg.AddMutateFunc(&cmapi.CertificateRequest{}, certificaterequests.MutateCreate); err != nil {
		return err
	}
	if err := reg.AddMutateUpdateFunc(&cmapi.CertificateRequest{}, certificaterequests.MutateUpdate); err != nil {
		return err
	}

	return nil
}
