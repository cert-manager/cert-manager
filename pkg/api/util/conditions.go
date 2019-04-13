/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package util

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"k8s.io/utils/clock"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// Clock is defined as a package var so it can be stubbed out during tests.
var Clock clock.Clock = clock.RealClock{}

// IssuerHasCondition will return true if the given GenericIssuer has a
// condition matching the provided IssuerCondition.
// Only the Type and Status field will be used in the comparison, meaning that
// this function will return 'true' even if the Reason, Message and
// LastTransitionTime fields do not match.
func IssuerHasCondition(i cmapi.GenericIssuer, c cmapi.IssuerCondition) bool {
	if i == nil {
		return false
	}
	existingConditions := i.GetStatus().Conditions
	for _, cond := range existingConditions {
		if c.Type == cond.Type && c.Status == cond.Status {
			return true
		}
	}
	return false
}

// SetIssuerCondition will set a 'condition' on the given GenericIssuer.
// - If no condition of the same type already exists, the condition will be
//   inserted with the LastTransitionTime set to the current time.
// - If a condition of the same type and state already exists, the condition
//   will be updated but the LastTransitionTime will not be modified.
// - If a condition of the same type and different state already exists, the
//   condition will be updated and the LastTransitionTime set to the current
//   time.
// This function works with both Issuer and ClusterIssuer resources.
func SetIssuerCondition(i cmapi.GenericIssuer, conditionType cmapi.IssuerConditionType, status cmapi.ConditionStatus, reason, message string) {
	newCondition := cmapi.IssuerCondition{
		Type:    conditionType,
		Status:  status,
		Reason:  reason,
		Message: message,
	}

	nowTime := metav1.NewTime(Clock.Now())
	newCondition.LastTransitionTime = nowTime

	// Search through existing conditions
	for idx, cond := range i.GetStatus().Conditions {
		// Skip unrelated conditions
		if cond.Type != conditionType {
			continue
		}

		// If this update doesn't contain a state transition, we don't update
		// the conditions LastTransitionTime to Now()
		if cond.Status == status {
			newCondition.LastTransitionTime = cond.LastTransitionTime
		} else {
			klog.Infof("Found status change for Issuer %q condition %q: %q -> %q; setting lastTransitionTime to %v", i.GetObjectMeta().Name, conditionType, cond.Status, status, nowTime.Time)
		}

		// Overwrite the existing condition
		i.GetStatus().Conditions[idx] = newCondition
		return
	}

	// If we've not found an existing condition of this type, we simply insert
	// the new condition into the slice.
	i.GetStatus().Conditions = append(i.GetStatus().Conditions, newCondition)
	klog.Infof("Setting lastTransitionTime for Issuer %q condition %q to %v", i.GetObjectMeta().Name, conditionType, nowTime.Time)
}

// CertificateHasCondition will return true if the given Certificate has a
// condition matching the provided CertificateCondition.
// Only the Type and Status field will be used in the comparison, meaning that
// this function will return 'true' even if the Reason, Message and
// LastTransitionTime fields do not match.
func CertificateHasCondition(crt *cmapi.Certificate, c cmapi.CertificateCondition) bool {
	if crt == nil {
		return false
	}
	existingConditions := crt.Status.Conditions
	for _, cond := range existingConditions {
		if c.Type == cond.Type && c.Status == cond.Status {
			return true
		}
	}
	return false
}

// SetCertificateCondition will set a 'condition' on the given Certificate.
// - If no condition of the same type already exists, the condition will be
//   inserted with the LastTransitionTime set to the current time.
// - If a condition of the same type and state already exists, the condition
//   will be updated but the LastTransitionTime will not be modified.
// - If a condition of the same type and different state already exists, the
//   condition will be updated and the LastTransitionTime set to the current
//   time.
func SetCertificateCondition(crt *cmapi.Certificate, conditionType cmapi.CertificateConditionType, status cmapi.ConditionStatus, reason, message string) {
	newCondition := cmapi.CertificateCondition{
		Type:    conditionType,
		Status:  status,
		Reason:  reason,
		Message: message,
	}

	nowTime := metav1.NewTime(Clock.Now())
	newCondition.LastTransitionTime = nowTime

	// Search through existing conditions
	for idx, cond := range crt.Status.Conditions {
		// Skip unrelated conditions
		if cond.Type != conditionType {
			continue
		}

		// If this update doesn't contain a state transition, we don't update
		// the conditions LastTransitionTime to Now()
		if cond.Status == status {
			newCondition.LastTransitionTime = cond.LastTransitionTime
		} else {
			klog.Infof("Found status change for Certificate %q condition %q: %q -> %q; setting lastTransitionTime to %v", crt.Name, conditionType, cond.Status, status, nowTime.Time)
		}

		// Overwrite the existing condition
		crt.Status.Conditions[idx] = newCondition
		return
	}

	// If we've not found an existing condition of this type, we simply insert
	// the new condition into the slice.
	crt.Status.Conditions = append(crt.Status.Conditions, newCondition)
	klog.Infof("Setting lastTransitionTime for Certificate %q condition %q to %v", crt.Name, conditionType, nowTime.Time)
}
