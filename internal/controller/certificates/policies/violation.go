/*
Copyright 2024 The cert-manager Authors.

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

package policies

type Violation[R Reason] struct {
	Reason  R
	Message string
}

func NewInvalidInputViolation(reason InvalidInputReason, message string) *Violation[InvalidInputReason] {
	return &Violation[InvalidInputReason]{
		Reason:  reason,
		Message: message,
	}
}

func MaybeValidation[R Reason](invalidInput *Violation[InvalidInputReason]) *Violation[MaybeReason[R]] {
	return &Violation[MaybeReason[R]]{
		Reason: MaybeReason[R]{
			invalidInput: invalidInput.Reason,
		},
		Message: invalidInput.Message,
	}
}

func NewIssuanceViolation(reason IssuanceReason, message string) *Violation[MaybeReason[IssuanceReason]] {
	return &Violation[MaybeReason[IssuanceReason]]{
		Reason: MaybeReason[IssuanceReason]{
			validInput: reason,
		},
		Message: message,
	}
}

func NewPostIssuanceViolation(reason PostIssuanceReason, message string) *Violation[MaybeReason[PostIssuanceReason]] {
	return &Violation[MaybeReason[PostIssuanceReason]]{
		Reason: MaybeReason[PostIssuanceReason]{
			validInput: reason,
		},
		Message: message,
	}
}
