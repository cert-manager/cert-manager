/*
Copyright 2022 The cert-manager Authors.

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

package values

type Probe struct {
	// Minimum consecutive failures for the probe to be considered failed after having succeeded.
	// +optional
	FailureThreshold int32 `json:"failureThreshold"`

	// Number of seconds after the container has started before liveness probes are initiated.
	// ref: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
	// +optional
	InitialDelaySeconds int32 `json:"initialDelaySeconds"`

	// How often (in seconds) to perform the probe.
	// +optional
	PeriodSeconds int32 `json:"periodSeconds"`

	// Minimum consecutive successes for the probe to be considered successful after having failed.
	// +optional
	SuccessThreshold int32 `json:"successThreshold"`

	// Number of seconds after which the probe times out.
	// ref: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle#container-probes
	// +optional
	TimeoutSeconds int32 `json:"timeoutSeconds"`
}
