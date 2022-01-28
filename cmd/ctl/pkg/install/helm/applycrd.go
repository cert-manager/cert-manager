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

package helm

import (
	"log"
	"time"

	"helm.sh/helm/v3/pkg/action"
	"k8s.io/cli-runtime/pkg/resource"
)

// CreateCRDs creates cert manager CRDs. Before calling this function, we
// made sure that the CRDs are not yet installed on the cluster.
func CreateCRDs(allCRDs []*resource.Info, cfg *action.Configuration) error {
	log.Printf("Creating the cert-manager CRDs")
	// Create all CRDs
	rr, err := cfg.KubeClient.Create(allCRDs)
	if err != nil {
		return err
	}
	createdCRDs := rr.Created

	// Invalidate the local cache, since it will not have the new CRDs
	// present.
	discoveryClient, err := cfg.RESTClientGetter.ToDiscoveryClient()
	if err != nil {
		return err
	}

	log.Printf("Clearing discovery cache")
	discoveryClient.Invalidate()

	// Give time for the CRD to be recognized.
	if err := cfg.KubeClient.Wait(createdCRDs, 60*time.Second); err != nil {
		return err
	}

	// Make sure to force a rebuild of the cache.
	if _, err := discoveryClient.ServerGroups(); err != nil {
		return err
	}

	return nil
}
