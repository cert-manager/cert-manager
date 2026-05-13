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

// Package scheduler selects which ACME Challenge resources may be marked
// processing at a given time.
//
// The scheduler has two main jobs:
//   - apply a coarse global concurrency limit; and
//   - avoid running challenges that are likely to conflict with one another.
//
// It does not attempt to model CA-specific rate limits, tenant fairness, or
// per-Issuer quotas. In particular, it does not prevent a large number of
// independent challenges from monopolising the shared backlog. This package is
// therefore best thought of as a simple back-pressure and conflict-avoidance
// mechanism rather than a complete rate-limit or fairness controller.
//
// The conflict key is intentionally conservative: challenges with the same DNS
// name and ACME challenge type are treated as conflicting even if their solver
// backends differ. This is because cert-manager's self-check and the ACME
// server validate externally visible targets, not cert-manager's internal
// solver configuration.
//
// For example:
//   - HTTP01 validation is still against the same hostname even if different
//     ingress classes, named ingresses, or gateway routes are configured.
//   - DNS01 validation is still against the same _acme-challenge name even if
//     different DNS provider backends are configured.
//
// A single cert-manager instance performs self-checks from one network and DNS
// viewpoint only. If two challenges for the same DNS name rely on different
// externally visible paths, that instance will still generally observe only one
// of them. As a result, differing solver backends do not reliably imply
// independent ACME-visible validation paths, so the scheduler keeps the key
// coarse by design.
package scheduler
