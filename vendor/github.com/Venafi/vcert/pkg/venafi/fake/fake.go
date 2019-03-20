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

package fake

import (
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
)

func (c *Connector) SetBaseURL(url string) error {
	return nil
}

//GenerateRequest creates a new certificate request, based on the zone/policy configuration and the user data
func (c *Connector) GenerateRequest(config *endpoint.ZoneConfiguration, req *certificate.Request) (err error) {

	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR:
		switch req.KeyType {
		case certificate.KeyTypeECDSA:
			req.PrivateKey, err = certificate.GenerateECDSAPrivateKey(req.KeyCurve)
		case certificate.KeyTypeRSA:
			if req.KeyLength == 0 {
				req.KeyLength = 2048
			}
			req.PrivateKey, err = certificate.GenerateRSAPrivateKey(req.KeyLength)
		default:
			return fmt.Errorf("Unable to generate certificate request, key type %s is not supported", req.KeyType.String())
		}
		if err != nil {
			return err
		}
		err = certificate.GenerateRequest(req, req.PrivateKey)
		if err != nil {
			return err
		}
		req.CSR = pem.EncodeToMemory(certificate.GetCertificateRequestPEMBlock(req.CSR))

	case certificate.UserProvidedCSR:
		if req.CSR == nil {
			return fmt.Errorf("CSR was supposed to be provided by user, but it's empty")
		}

	case certificate.ServiceGeneratedCSR:
		req.CSR = nil

	default:
		return fmt.Errorf("Unexpected option in PrivateKeyOrigin")
	}

	return nil
}
