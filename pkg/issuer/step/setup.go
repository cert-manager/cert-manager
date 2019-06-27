/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package step

import (
	"context"
	"fmt"
	"strings"

	"github.com/jetstack/cert-manager/pkg/api/util"
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Setup initializes the issuer after verifying the connection with step certificates.
func (s *Step) Setup(ctx context.Context) error {
	resp, err := s.provisioner.Health()
	if err != nil {
		util.SetIssuerCondition(s.issuer, certmanager.IssuerConditionReady, certmanager.ConditionFalse, "ErrorHealth", "Failed to connect to step certificates")
		return fmt.Errorf("failed to connect to step certificate: %v", err)
	}
	if !strings.EqualFold(resp.Status, "ok") {
		util.SetIssuerCondition(s.issuer, certmanager.IssuerConditionReady, certmanager.ConditionFalse, "ErrorHealth", fmt.Sprintf("Unexpected health status %s on step certificates", resp.Status))
		return fmt.Errorf("unexpected step certificate status: %s", resp.Status)
	}

	// Mark issuer as ready
	util.SetIssuerCondition(s.issuer, certmanager.IssuerConditionReady, certmanager.ConditionTrue, "StepVerified", "Step verified")
	return nil
}
