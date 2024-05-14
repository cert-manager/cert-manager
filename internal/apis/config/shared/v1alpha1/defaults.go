/*
Copyright 2023 The cert-manager Authors.

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

package v1alpha1

import (
	"time"

	"github.com/cert-manager/cert-manager/pkg/apis/config/shared/v1alpha1"
)

var (
	defaultLeafDuration = time.Hour * 24 * 7

	defaultLeaderElect                 = true
	defaultLeaderElectionNamespace     = "kube-system"
	defaultLeaderElectionLeaseDuration = 60 * time.Second
	defaultLeaderElectionRenewDeadline = 40 * time.Second
	defaultLeaderElectionRetryPeriod   = 15 * time.Second
)

func SetDefaults_DynamicServingConfig(obj *v1alpha1.DynamicServingConfig) {
	if obj.LeafDuration.IsZero() {
		obj.LeafDuration = v1alpha1.DurationFromTime(defaultLeafDuration)
	}
}

func SetDefaults_LeaderElectionConfig(obj *v1alpha1.LeaderElectionConfig) {
	if obj.Enabled == nil {
		obj.Enabled = &defaultLeaderElect
	}

	if obj.Namespace == "" {
		obj.Namespace = defaultLeaderElectionNamespace
	}

	if obj.LeaseDuration.IsZero() {
		obj.LeaseDuration = v1alpha1.DurationFromTime(defaultLeaderElectionLeaseDuration)
	}

	if obj.RenewDeadline.IsZero() {
		obj.RenewDeadline = v1alpha1.DurationFromTime(defaultLeaderElectionRenewDeadline)
	}

	if obj.RetryPeriod.IsZero() {
		obj.RetryPeriod = v1alpha1.DurationFromTime(defaultLeaderElectionRetryPeriod)
	}
}
