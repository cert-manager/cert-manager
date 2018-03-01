package v1alpha1

import "time"

const (
	// minimum permitted certificate duration by cert-manager
	MinimumCertificateDuration = time.Hour

	// default certificate duration if Issuer.spec.duration is not set
	DefaultCertificateDuration = time.Hour * 24 * 90

	// minimum certificate duration before certificate expiration
	MinimumRenewBefore = time.Minute * 5

	// Default duration before certificate expiration if  Issuer.spec.renewBefore is not set
	DefaultRenewBefore = time.Hour * 24 * 30
)
