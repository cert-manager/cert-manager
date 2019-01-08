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

	"github.com/onsi/ginkgo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

const (
	// Poll is how often the API is polled in Wait operations by default
	Poll = time.Second * 2

	// PodStartTimeout is the default amount of time to wait in pod start operations
	PodStartTimeout = time.Minute * 2
)

// WaitForAllPodsRunningInNamespace waits default amount of time (PodStartTimeout)
// for all pods in the specified namespace to become running.
func (h *Helper) WaitForAllPodsRunningInNamespace(ns string) error {
	return h.WaitForAllPodsRunningInNamespaceTimeout(ns, PodStartTimeout)
}

func (h *Helper) WaitForAllPodsRunningInNamespaceTimeout(ns string, timeout time.Duration) error {
	ginkgo.By("Waiting " + timeout.String() + " for all pods in namespace '" + ns + "' to be Ready")
	return wait.PollImmediate(Poll, timeout, func() (bool, error) {
		pods, err := h.KubeClient.CoreV1().Pods(ns).List(metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		if len(pods.Items) == 0 {
			log.Logf("No pods found in namespace %s - checking again...")
			return false, nil
		}

		var errs []string
		for _, p := range pods.Items {
			c := GetPodReadyCondition(p.Status)
			if c == nil {
				errs = append(errs, fmt.Sprintf("Pod %q not ready (no Ready condition)", p.Name))
				continue
			}
			if c.Reason == "PodCompleted" {
				log.Logf("Pod %q has Completed, assuming it is ready/expected", p.Name)
				continue
			}
			// This pod does not have the ready condition set to True
			if c.Status != corev1.ConditionTrue {
				errs = append(errs, fmt.Sprintf("Pod %q not ready: %s", p.Name, c.String()))
			}
		}

		if len(errs) > 0 {
			for _, err := range errs {
				log.Logf(err)
			}
			return false, nil
		}

		return true, nil
	})
}

// IsPodReady returns true if a pod is ready; false otherwise.
func IsPodReady(pod *corev1.Pod) bool {
	return IsPodReadyConditionTrue(pod.Status)
}

// IsPodReadyConditionTrue returns true if a pod is ready; false otherwise.
func IsPodReadyConditionTrue(status corev1.PodStatus) bool {
	condition := GetPodReadyCondition(status)
	return condition != nil && condition.Status == corev1.ConditionTrue
}

// GetPodReadyCondition extracts the pod ready condition from the given status and returns that.
// Returns nil if the condition is not present.
func GetPodReadyCondition(status corev1.PodStatus) *corev1.PodCondition {
	_, condition := GetPodCondition(&status, corev1.PodReady)
	return condition
}

// GetPodCondition extracts the provided condition from the given status and returns that.
// Returns nil and -1 if the condition is not present, and the index of the located condition.
func GetPodCondition(status *corev1.PodStatus, conditionType corev1.PodConditionType) (int, *corev1.PodCondition) {
	if status == nil {
		return -1, nil
	}
	for i := range status.Conditions {
		if status.Conditions[i].Type == conditionType {
			return i, &status.Conditions[i]
		}
	}
	return -1, nil
}
