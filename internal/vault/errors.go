/*
Copyright 2026 The cert-manager Authors.

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

package vault

import (
	"errors"
	"fmt"

	vault "github.com/hashicorp/vault/api"

	cmerrors "github.com/cert-manager/cert-manager/pkg/util/errors"
)

const (
	messageTemplateNonVaultErrorResponse = "the Vault server returned an HTTP %d response which is not a Vault error response; the response body has been omitted and can be found in the cert-manager logs"

	// maxVaultErrorMessageLength bounds how much of an error is copied into an
	// Issuer status condition or a Kubernetes Event.
	maxVaultErrorMessageLength = 1024

	// maxVaultErrorLogLength bounds how much of an error is written to the logs.
	// Logs are not persisted to the API server so this can be more generous than
	// maxVaultErrorMessageLength, but an unbounded response body must not be
	// able to flood the log either.
	maxVaultErrorLogLength = 8192
)

// SafeErrorMessage renders err for inclusion in an Issuer status condition and
// in the Kubernetes Events raised alongside it. Both are persisted to the API
// server and are readable by anyone who can read the Issuer, so they must not
// carry content chosen by whatever spec.vault.server points at.
func SafeErrorMessage(err error) string {
	// Use errors.AsType rather than a bare type assertion so that a response
	// error which has been wrapped on its way up cannot bypass this check.
	respErr, ok := errors.AsType[*vault.ResponseError](err)
	if !ok {
		// Not a response from the server: this was raised locally or by the
		// Kubernetes API and carries no remote content.
		return cmerrors.TruncateMessage(err.Error(), maxVaultErrorMessageLength)
	}

	// RawError is set when the body could not be decoded as a Vault error
	// response, in which case Errors holds the raw body verbatim. That body was
	// not written by Vault, so it is not safe to reflect.
	if respErr.RawError {
		return fmt.Sprintf(messageTemplateNonVaultErrorResponse, respErr.StatusCode)
	}

	return cmerrors.TruncateMessage(err.Error(), maxVaultErrorMessageLength)
}

// LoggableErrorMessage renders err for the cert-manager logs, where the full
// response details are useful for debugging.
func LoggableErrorMessage(err error) string {
	return cmerrors.TruncateMessage(err.Error(), maxVaultErrorLogLength)
}
