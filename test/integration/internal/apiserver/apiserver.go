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

package apiserver

import (
	"testing"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func init() {
	// Set environment variables for controller-runtime's envtest package.
	// This is done once as we cannot scope environment variables to a single
	// invocation of RunControlPlane due to envtest's design.
	setUpEnvTestEnv()
}

type StopFunc func()

func RunBareControlPlane(t *testing.T) (*envtest.Environment, StopFunc) {
	// Here we start the API server so its address can be given to the webhook on
	// start. We then restart the API with the CRDs in the webhook.
	env := &envtest.Environment{
		AttachControlPlaneOutput: false,
	}

	if _, err := env.Start(); err != nil {
		t.Fatalf("failed to start control plane: %v", err)
	}

	// Ensure we set a User Agent for the API server client.
	env.Config.UserAgent = rest.DefaultKubernetesUserAgent()

	return env, func() {
		if err := env.Stop(); err != nil {
			t.Fatalf("failed to shut down control plane: %v", err)
		}
	}
}
