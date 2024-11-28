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

package venafi

import (
	"context"
	"fmt"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func (v *Venafi) Setup(ctx context.Context, issuer v1.GenericIssuer) error {
	client, err := v.clientBuilder(v.resourceNamespace, v.secretsLister, v.issuer, v.Metrics, v.log, v.userAgent)
	if err != nil {
		return fmt.Errorf("error building Venafi client: %v", err)
	}
	err = client.Ping()
	if err != nil {
		return fmt.Errorf("error pinging Venafi API: %v", err)
	}

	err = client.VerifyCredentials()
	if err != nil {
		return fmt.Errorf("error verifying Venafi credentials: %v", err)
	}

	v.log.V(logf.DebugLevel).Info("Venafi issuer started")

	return nil
}
