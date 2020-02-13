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

package helper

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

func (h *Helper) WaitForIssuerStatusFunc(ns, name string, fn func(*v1alpha2.Issuer) (bool, error)) error {
	pollErr := wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {
			issuer, err := h.CMClient.CertmanagerV1alpha2().Issuers(ns).Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Issuer %q: %v", name, err)
			}
			return fn(issuer)
		})

	if pollErr != nil {
		log.Logf("error waiting for Issuer to reach status: %s", pollErr)
		h.Kubectl("").DescribeResource("issuers", name)
		return pollErr
	}

	return nil
}

// WaitForIssuerCondition waits for the status of the named issuer to contain
// a condition whose type and status matches the supplied one.
func (h *Helper) WaitForIssuerCondition(ns, name string, condition v1alpha2.IssuerCondition) error {
	pollErr := wait.PollImmediate(500*time.Millisecond, time.Minute*10,
		func() (bool, error) {
			log.Logf("Waiting for issuer %v condition %#v", name, condition)
			issuer, err := h.CMClient.CertmanagerV1alpha2().Issuers(ns).Get(name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting Issuer %q: %v", name, err)
			}

			return apiutil.IssuerHasCondition(issuer, condition), nil
		},
	)

	return h.wrapErrorWithIssuerStatusCondition(pollErr, ns, name, condition.Type)
}

// try to retrieve last condition to help diagnose tests.
func (h *Helper) wrapErrorWithIssuerStatusCondition(pollErr error, ns, name string, conditionType v1alpha2.IssuerConditionType) error {
	if pollErr == nil {
		return nil
	}

	log.Logf("error waiting for Issuer to reach status: %s", pollErr)
	h.Kubectl(ns).DescribeResource("issuer", name)

	issuer, err := h.CMClient.CertmanagerV1alpha2().Issuers(ns).Get(name, metav1.GetOptions{})
	if err != nil {
		return pollErr
	}

	for _, cond := range issuer.GetStatus().Conditions {
		if cond.Type == conditionType {
			return fmt.Errorf("%s: Last Status: '%s' Reason: '%s', Message: '%s'", pollErr.Error(), cond.Status, cond.Reason, cond.Message)
		}

	}

	return pollErr
}

// WaitForClusterIssuerCondition waits for the status of the named issuer to contain
// a condition whose type and status matches the supplied one.
func (h *Helper) WaitForClusterIssuerCondition(name string, condition v1alpha2.IssuerCondition) error {
	pollErr := wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {
			log.Logf("Waiting for clusterissuer %v condition %#v", name, condition)
			issuer, err := h.CMClient.CertmanagerV1alpha2().ClusterIssuers().Get(name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting ClusterIssuer %v: %v", name, err)
			}

			return apiutil.IssuerHasCondition(issuer, condition), nil
		},
	)
	return h.wrapErrorWithClusterIssuerStatusCondition(pollErr, name, condition.Type)
}

// try to retrieve last condition to help diagnose tests.
func (h *Helper) wrapErrorWithClusterIssuerStatusCondition(pollErr error, name string, conditionType v1alpha2.IssuerConditionType) error {
	if pollErr == nil {
		return nil
	}

	log.Logf("error waiting for ClusterIssuer to reach status: %s", pollErr)
	h.Kubectl("").DescribeResource("clusterissuer", name)

	issuer, err := h.CMClient.CertmanagerV1alpha2().ClusterIssuers().Get(name, metav1.GetOptions{})
	if err != nil {
		return pollErr
	}

	for _, cond := range issuer.GetStatus().Conditions {
		if cond.Type == conditionType {
			return fmt.Errorf("%s: Last Status: '%s' Reason: '%s', Message: '%s'", pollErr.Error(), cond.Status, cond.Reason, cond.Message)
		}

	}

	return pollErr
}
