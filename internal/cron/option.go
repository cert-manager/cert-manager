// +skip_license_check

/*
This file contains portions of code directly taken from the 'robfig/cron' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package cron

import (
	"time"
)

// Option represents a modification to the default behavior of a Cron.
type Option func(*Cron)

// WithLocation overrides the timezone of the cron instance.
func WithLocation(loc *time.Location) Option {
	return func(c *Cron) {
		c.location = loc
	}
}

// WithSeconds overrides the parser used for interpreting job schedules to
// include a seconds field as the first one.
func WithSeconds() Option {
	return WithParser(NewParser(
		Second | Minute | Hour | Dom | Month | Dow | Descriptor,
	))
}

// WithParser overrides the parser used for interpreting job schedules.
func WithParser(p Parser) Option {
	return func(c *Cron) {
		c.parser = p
	}
}

// WithLogger uses the provided logger.
func WithLogger(logger Logger) Option {
	return func(c *Cron) {
		c.logger = logger
	}
}
