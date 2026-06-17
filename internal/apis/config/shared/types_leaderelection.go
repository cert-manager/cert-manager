/*
Copyright 2021 The cert-manager Authors.

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

package shared

import "time"

type LeaderElectionConfig struct {
	// If true, cert-manager will perform leader election between instances to
	// ensure no more than one instance of cert-manager operates at a time
	Enabled bool

	// Namespace used to perform leader election. Only used if leader election is enabled
	Namespace string

	// The duration that non-leader candidates will wait after observing a leadership
	// renewal until attempting to acquire leadership of a led but unrenewed leader
	// slot. This is effectively the maximum duration that a leader can be stopped
	// before it is replaced by another candidate. This is only applicable if leader
	// election is enabled.
	LeaseDuration time.Duration

	// The interval between attempts by the acting master to renew a leadership slot
	// before it stops leading. This must be less than or equal to the lease duration.
	// This is only applicable if leader election is enabled.
	RenewDeadline time.Duration

	// The duration the clients should wait between attempting acquisition and renewal
	// of a leadership. This is only applicable if leader election is enabled.
	RetryPeriod time.Duration
}
