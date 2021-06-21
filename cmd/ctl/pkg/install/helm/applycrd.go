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
	"errors"
	"fmt"
	"log"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/cli-runtime/pkg/resource"

	"helm.sh/helm/v3/pkg/action"
)

type CRDsPolicy int

const (
	Skip CRDsPolicy = iota
	Create
	CreateReplace
)

func (policy CRDsPolicy) String() string {
	return [...]string{"Skip", "Create", "CreateReplace"}[policy]
}

// This has been adapted from https://github.com/fluxcd/helm-controller/blob/main/internal/runner/runner.go#L212
func ApplyCRDs(policy CRDsPolicy, allCrds []*resource.Info, cfg *action.Configuration) error {
	log.Printf("apply CRDs with policy %v", policy)

	totalItems := []*resource.Info{}
	switch policy {
	case Skip:
		break
	case CreateReplace:
		// 1. Update exising crds
		originalCrds, err := FetchResources(allCrds, cfg.KubeClient)
		if err != nil {
			return nil
		}

		if rr, err := cfg.KubeClient.Update(originalCrds, allCrds, true); err != nil {
			log.Printf("failed to apply CRD %s", err)
			return errors.New(fmt.Sprintf("failed to apply CRD %s", err))
		} else {
			if rr != nil {
				if rr.Created != nil {
					totalItems = append(totalItems, rr.Created...)
				}
				if rr.Updated != nil {
					totalItems = append(totalItems, rr.Updated...)
				}
				if rr.Deleted != nil {
					totalItems = append(totalItems, rr.Deleted...)
				}
			}
		}
		// 2. Passthrough and install all missing crds
	case Create:
		for i := range allCrds {
			if rr, err := cfg.KubeClient.Create(allCrds[i : i+1]); err != nil {
				crdName := allCrds[i].Name
				// If the error is CRD already exists, continue.
				if apierrors.IsAlreadyExists(err) {
					log.Printf("CRD %s is already present. Skipping.", crdName)
					if rr != nil && rr.Created != nil {
						totalItems = append(totalItems, rr.Created...)
					}
					continue
				}
				log.Printf("failed to create CRD %s: %s", crdName, err)
				return errors.New(fmt.Sprintf("failed to create CRD %s: %s", crdName, err))
			} else {
				if rr != nil && rr.Created != nil {
					totalItems = append(totalItems, rr.Created...)
				}
			}
		}
		break
	}
	if len(totalItems) > 0 {
		// Invalidate the local cache, since it will not have the new CRDs
		// present.
		discoveryClient, err := cfg.RESTClientGetter.ToDiscoveryClient()
		if err != nil {
			log.Printf("Error in cfg.RESTClientGetter.ToDiscoveryClient(): %s", err)
			return err
		}
		log.Printf("Clearing discovery cache")
		discoveryClient.Invalidate()
		// Give time for the CRD to be recognized.
		if err := cfg.KubeClient.Wait(totalItems, 60*time.Second); err != nil {
			log.Printf("Error waiting for items: %s", err)
			return err
		}
		// Make sure to force a rebuild of the cache.
		discoveryClient.ServerGroups()
	}
	return nil
}
