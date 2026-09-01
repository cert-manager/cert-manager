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
	//
	// This check is best-effort rather than a guarantee. RawError is false
	// whenever the body parsed as Vault's error envelope, which is not the same
	// as the body having been written by Vault: any endpoint that responds with
	// {"errors": ["..."]} decodes cleanly, and its strings are still reflected
	// here. Unlike ACME, whose problem documents carry a
	// urn:ietf:params:acme:error prefix we can key on, a Vault error response
	// has no marker that a hostile endpoint could not also produce. The
	// truncation below is what bounds that residual case.
	if respErr.RawError {
		return fmt.Sprintf(messageTemplateNonVaultErrorResponse, respErr.StatusCode)
	}

	return cmerrors.TruncateMessage(err.Error(), maxVaultErrorMessageLength)
}

// LoggableErrorMessage renders err for the cert-manager logs, where the full
// response details are useful for debugging.
func LoggableErrorMessage(err error) string {
	// Recover the unsanitised error if this one left the package through
	// sanitizeError, so that the logs keep the detail that was withheld from the
	// API server.
	if sanitized, ok := errors.AsType[*sanitizedError](err); ok {
		err = sanitized.err
	}

	return cmerrors.TruncateMessage(err.Error(), maxVaultErrorLogLength)
}

// sanitizedError renders as a message that is safe to persist to the API server
// while keeping the original error reachable, both for the logs via
// LoggableErrorMessage and for callers matching on it with errors.Is and
// errors.As.
type sanitizedError struct {
	safe string
	err  error
}

func (e *sanitizedError) Error() string { return e.safe }

func (e *sanitizedError) Unwrap() error { return e.err }

// sanitizeError prepares err to leave this package. Every caller of New, Sign
// and IsVaultInitializedAndUnsealed copies the error it gets back into a
// Kubernetes Event and into the status of an Issuer, a CertificateRequest or a
// CertificateSigningRequest, all of which are persisted to the API server and
// readable by anyone who can read the resource. Sanitising here rather than at
// each of those sinks means a new caller cannot reintroduce the disclosure by
// forgetting to call SafeErrorMessage.
func sanitizeError(err error) error {
	if err == nil {
		return nil
	}

	// Only an error carrying a response can hold content chosen by whatever
	// spec.vault.server points at. Leaving every other error untouched keeps it
	// matchable by the callers that type-assert on it without going through
	// errors.As, notably cmerrors.IsInvalidData.
	if _, ok := errors.AsType[*vault.ResponseError](err); !ok {
		return err
	}

	safe := SafeErrorMessage(err)
	if safe == err.Error() {
		// Nothing was withheld, so there is no reason to obscure the chain.
		return err
	}

	return &sanitizedError{safe: safe, err: err}
}
