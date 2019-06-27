package provisioner

import (
	"time"

	"github.com/pkg/errors"
)

// Claims so that individual provisioners can override global claims.
type Claims struct {
	MinTLSDur      *Duration `json:"minTLSCertDuration,omitempty"`
	MaxTLSDur      *Duration `json:"maxTLSCertDuration,omitempty"`
	DefaultTLSDur  *Duration `json:"defaultTLSCertDuration,omitempty"`
	DisableRenewal *bool     `json:"disableRenewal,omitempty"`
}

// Claimer is the type that controls claims. It provides an interface around the
// current claim and the global one.
type Claimer struct {
	global Claims
	claims *Claims
}

// NewClaimer initializes a new claimer with the given claims.
func NewClaimer(claims *Claims, global Claims) (*Claimer, error) {
	c := &Claimer{global: global, claims: claims}
	return c, c.Validate()
}

// Claims returns the merge of the inner and global claims.
func (c *Claimer) Claims() Claims {
	disableRenewal := c.IsDisableRenewal()
	return Claims{
		MinTLSDur:      &Duration{c.MinTLSCertDuration()},
		MaxTLSDur:      &Duration{c.MaxTLSCertDuration()},
		DefaultTLSDur:  &Duration{c.DefaultTLSCertDuration()},
		DisableRenewal: &disableRenewal,
	}
}

// DefaultTLSCertDuration returns the default TLS cert duration for the
// provisioner. If the default is not set within the provisioner, then the global
// default from the authority configuration will be used.
func (c *Claimer) DefaultTLSCertDuration() time.Duration {
	if c.claims == nil || c.claims.DefaultTLSDur == nil {
		return c.global.DefaultTLSDur.Duration
	}
	return c.claims.DefaultTLSDur.Duration
}

// MinTLSCertDuration returns the minimum TLS cert duration for the provisioner.
// If the minimum is not set within the provisioner, then the global
// minimum from the authority configuration will be used.
func (c *Claimer) MinTLSCertDuration() time.Duration {
	if c.claims == nil || c.claims.MinTLSDur == nil {
		return c.global.MinTLSDur.Duration
	}
	return c.claims.MinTLSDur.Duration
}

// MaxTLSCertDuration returns the maximum TLS cert duration for the provisioner.
// If the maximum is not set within the provisioner, then the global
// maximum from the authority configuration will be used.
func (c *Claimer) MaxTLSCertDuration() time.Duration {
	if c.claims == nil || c.claims.MaxTLSDur == nil {
		return c.global.MaxTLSDur.Duration
	}
	return c.claims.MaxTLSDur.Duration
}

// IsDisableRenewal returns if the renewal flow is disabled for the
// provisioner. If the property is not set within the provisioner, then the
// global value from the authority configuration will be used.
func (c *Claimer) IsDisableRenewal() bool {
	if c.claims == nil || c.claims.DisableRenewal == nil {
		return *c.global.DisableRenewal
	}
	return *c.claims.DisableRenewal
}

// Validate validates and modifies the Claims with default values.
func (c *Claimer) Validate() error {
	var (
		min = c.MinTLSCertDuration()
		max = c.MaxTLSCertDuration()
		def = c.DefaultTLSCertDuration()
	)
	switch {
	case min <= 0:
		return errors.Errorf("claims: MinTLSCertDuration must be greater than 0")
	case max <= 0:
		return errors.Errorf("claims: MaxTLSCertDuration must be greater than 0")
	case def <= 0:
		return errors.Errorf("claims: DefaultTLSCertDuration must be greater than 0")
	case max < min:
		return errors.Errorf("claims: MaxCertDuration cannot be less "+
			"than MinCertDuration: MaxCertDuration - %v, MinCertDuration - %v", max, min)
	case def < min:
		return errors.Errorf("claims: DefaultCertDuration cannot be less than MinCertDuration: DefaultCertDuration - %v, MinCertDuration - %v", def, min)
	case max < def:
		return errors.Errorf("claims: MaxCertDuration cannot be less than DefaultCertDuration: MaxCertDuration - %v, DefaultCertDuration - %v", max, def)
	default:
		return nil
	}
}
