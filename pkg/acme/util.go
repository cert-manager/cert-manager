package acme

import (
	v1alpha1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// IsFinalState will return true if the given ACME State is a 'final' state.
// This is either one of 'ready', 'failed' or 'expired'.
// The 'valid' state is a special case, as it is a final state for Challenges but
// not for Orders.
func IsFinalState(s v1alpha1.State) bool {
	switch s {
	case v1alpha1.Ready, v1alpha1.Failed, v1alpha1.Expired:
		return true
	}
	return false
}

func IsFailureState(s v1alpha1.State) bool {
	switch s {
	case v1alpha1.Failed, v1alpha1.Expired:
		return true
	}
	return false
}
