/*
Copyright 2026 The cert-manager Authors.

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

package route53

import (
	"sync"

	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// PendingChangesCache remembers the ID of a Route 53 record change which has
// been submitted but has not yet reached the INSYNC status, so that a retried
// Present or CleanUp resumes polling GetChange for the original change instead
// of submitting a duplicate ChangeResourceRecordSets request. Supply a single
// shared instance to every DNSProvider in the process, because a new
// DNSProvider is constructed for every challenge reconcile.
// See https://github.com/cert-manager/cert-manager/issues/9066
type PendingChangesCache struct {
	mu      sync.Mutex
	changes map[pendingChangeKey]pendingChange
}

type pendingChangeKey struct {
	fqdn  string
	value string
}

type pendingChange struct {
	action   route53types.ChangeAction
	changeID string
}

// NewPendingChangesCache returns an empty PendingChangesCache.
func NewPendingChangesCache() *PendingChangesCache {
	return &PendingChangesCache{
		changes: map[pendingChangeKey]pendingChange{},
	}
}

// get returns the ID of a pending change for the given action, fqdn and value.
// A pending change for the same record but a different action (e.g. an upsert
// pending when a delete is requested) is superseded, not resumed.
func (c *PendingChangesCache) get(action route53types.ChangeAction, fqdn, value string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	change, ok := c.changes[pendingChangeKey{fqdn: fqdn, value: value}]
	if !ok || change.action != action {
		return "", false
	}
	return change.changeID, true
}

func (c *PendingChangesCache) put(action route53types.ChangeAction, fqdn, value, changeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.changes[pendingChangeKey{fqdn: fqdn, value: value}] = pendingChange{action: action, changeID: changeID}
}

func (c *PendingChangesCache) delete(fqdn, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.changes, pendingChangeKey{fqdn: fqdn, value: value})
}
