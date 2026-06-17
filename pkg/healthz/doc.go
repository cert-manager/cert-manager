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

// Package healthz provides an HTTP server which responds to HTTP liveness probes
// and performs health checks.
//
// Currently it only checks that the LeaderElector has an up to date LeaderElectionRecord.
// Normally the parent process should exit if the LeaderElectionRecord is stale,
// but it is possible that the process is prevented from exiting by a bug,
// in which case this check will fail, the liveness probe will fail and then the
// Kubelet will restart the process.
// See the following issue and PR to understand how this problem was solved in
// Kubernetes:
// * [kube-controller-manager becomes deadlocked but still passes healthcheck](https://github.com/kubernetes/kubernetes/issues/70819)
// * [Report KCM as unhealthy if leader election is wedged](https://github.com/kubernetes/kubernetes/pull/70971)

package healthz
