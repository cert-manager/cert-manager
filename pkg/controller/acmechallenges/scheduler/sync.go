/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package scheduler

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	"github.com/jetstack/cert-manager/pkg/acme"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Sync will process a single ACME challenge resource in order to determine
// whether it can be scheduled for processing.
// This is currently extremelly primitive, and **will not** do intelligent
// things like bumping challenges that are for already expired or nearing expiry
// certificates to the 'front' of the queue.
//
// This may be something to do in future - we could use a resyncFunc to build
// a stack of challenges to process, and upon observation of a new challenge,
// re-evaluate the whole stack.
//
// For now, this function will simply be used to solve https://github.com/jetstack/cert-manager/issues/951
func (c *Controller) Sync(ctx context.Context, ch *cmapi.Challenge) error {
	// If the challenge is already in a final state, there is nothing more for
	// us to do.
	if acme.IsFinalState(ch.Status.State) {
		return nil
	}

	// If the challenge already has 'processing' set to true, there is nothing
	// more for us to do.
	// The 'acmechallenges' controller is responsible for setting this field to
	// false once processing has completed.
	if ch.Status.Processing == true {
		return nil
	}

	// Begin the scheduling algorithm! Here, we must evaluate all challenges
	// currently in the apiserver, and their current state, in order to determine
	// whether we can begin processing this challenge.

	allChallenges, err := c.challengeLister.List(labels.Everything())
	if err != nil {
		return err
	}

	// First, filter out all challenges that are *not* being processed.
	// With our naive scheduling algorithm, we only care about avoiding *duplicate*
	// challenges occurring at once.
	inFlightChallenges := removeNotProcessingChallenges(allChallenges)

	// if any other challenges are in-flight with the same challenge type and
	// same dnsName, we will *not* mark this challenge as processing
	for _, inFCh := range inFlightChallenges {
		if ch.Spec.DNSName == inFCh.Spec.DNSName && ch.Spec.Type == inFCh.Spec.Type {
			return fmt.Errorf("another %q challenge for challenge %q (domain %q) is in progress, waiting until it is complete before processing", ch.Spec.Type, ch.Name, ch.Spec.DNSName)
		}
	}

	// if there are no 'conflicts' detected above, then we can mark this challenge
	// as processing.
	ch.Status.Processing = true
	_, err = c.CMClient.CertmanagerV1alpha1().Challenges(ch.Namespace).Update(ch)
	if err != nil {
		return err
	}

	// we ignore the return value from waitForCacheSync - if it is false, the
	// controller will shutdown anyway.
	_ = c.waitForCacheSync()

	return nil
}

// removeNotProcessingChallenges will filter out challenges from the given slice
// that have status.processing set to false.
// TODO: we currently call this function on every call to Sync().
// In large deployments, this could cause high CPU and memory consumption as it
// works at O(n^2) complexity (i.e. for every challenge, we have to touch every
// challenge).
func removeNotProcessingChallenges(chs []*cmapi.Challenge) []*cmapi.Challenge {
	// TODO: there's probably a more efficient way to manage this that doesn't
	// involve constructing large slices and using append.
	var ret []*cmapi.Challenge
	for _, ch := range chs {
		if ch.Status.Processing {
			ret = append(ret, ch)
		}
	}
	return ret
}

func (c *Controller) waitForCacheSync() bool {
	return cache.WaitForCacheSync(c.stopCh, c.challengesHasSynced)
}
