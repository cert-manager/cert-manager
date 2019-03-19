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

package http

import (
	"fmt"
	"hash/adler32"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func podLabels(ch *v1alpha1.Challenge) map[string]string {
	domainHash := fmt.Sprintf("%d", adler32.Checksum([]byte(ch.Spec.DNSName)))
	tokenHash := fmt.Sprintf("%d", adler32.Checksum([]byte(ch.Spec.Token)))
	return map[string]string{
		// TODO: we need to support domains longer than 63 characters
		// this value should probably be hashed, and then the full plain text
		// value stored as an annotation to make it easier for users to read
		// see #425 for details: https://github.com/jetstack/cert-manager/issues/425
		domainLabelKey: domainHash,
		tokenLabelKey:  tokenHash,
	}
}

func (s *Solver) ensurePod(ch *v1alpha1.Challenge) (*corev1.Pod, error) {
	existingPods, err := s.getPodsForChallenge(ch)
	if err != nil {
		return nil, err
	}
	if len(existingPods) == 1 {
		return existingPods[0], nil
	}
	if len(existingPods) > 1 {
		errMsg := fmt.Sprintf("multiple challenge solver pods found for certificate '%s/%s'. Cleaning up existing pods.", ch.Namespace, ch.Name)
		klog.Infof(errMsg)
		err := s.cleanupPods(ch)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(errMsg)
	}

	klog.Infof("No existing HTTP01 challenge solver pod found for Certificate %q. One will be created.", ch.Namespace+"/"+ch.Name)
	return s.createPod(ch)
}

// getPodsForChallenge returns a list of pods that were created to solve
// the given challenge
func (s *Solver) getPodsForChallenge(ch *v1alpha1.Challenge) ([]*corev1.Pod, error) {
	podLabels := podLabels(ch)
	orderSelector := labels.NewSelector()
	for key, val := range podLabels {
		req, err := labels.NewRequirement(key, selection.Equals, []string{val})
		if err != nil {
			return nil, err
		}
		orderSelector = orderSelector.Add(*req)
	}

	podList, err := s.podLister.Pods(ch.Namespace).List(orderSelector)
	if err != nil {
		return nil, err
	}

	var relevantPods []*corev1.Pod
	for _, pod := range podList {
		if !metav1.IsControlledBy(pod, ch) {
			klog.Infof("Found pod %q with acme-order-url annotation set to that of Certificate %q"+
				"but it is not owned by the Certificate resource, so skipping it.", pod.Namespace+"/"+pod.Name, ch.Namespace+"/"+ch.Name)
			continue
		}
		relevantPods = append(relevantPods, pod)
	}

	return relevantPods, nil
}

func (s *Solver) cleanupPods(ch *v1alpha1.Challenge) error {
	pods, err := s.getPodsForChallenge(ch)
	if err != nil {
		return err
	}
	var errs []error
	for _, pod := range pods {
		// TODO: should we call DeleteCollection here? We'd need to somehow
		// also ensure ownership as part of that request using a FieldSelector.
		err := s.Client.CoreV1().Pods(pod.Namespace).Delete(pod.Name, nil)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return utilerrors.NewAggregate(errs)
}

// createPod will create a challenge solving pod for the given certificate,
// domain, token and key.
func (s *Solver) createPod(ch *v1alpha1.Challenge) (*corev1.Pod, error) {
	return s.Client.CoreV1().Pods(ch.Namespace).Create(s.buildPod(ch))
}

// buildPod will build a challenge solving pod for the given certificate,
// domain, token and key. It will not create it in the API server
func (s *Solver) buildPod(ch *v1alpha1.Challenge) *corev1.Pod {
	podLabels := podLabels(ch)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cm-acme-http-solver-",
			Namespace:    ch.Namespace,
			Labels:       podLabels,
			Annotations: map[string]string{
				"sidecar.istio.io/inject": "false",
			},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ch, challengeGvk)},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyOnFailure,
			Containers: []corev1.Container{
				{
					Name: "acmesolver",
					// TODO: use an image as specified as a config option
					Image:           s.Context.HTTP01SolverImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					// TODO: replace this with some kind of cmdline generator
					Args: []string{
						fmt.Sprintf("--listen-port=%d", acmeSolverListenPort),
						fmt.Sprintf("--domain=%s", ch.Spec.DNSName),
						fmt.Sprintf("--token=%s", ch.Spec.Token),
						fmt.Sprintf("--key=%s", ch.Spec.Key),
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    s.ACMEOptions.HTTP01SolverResourceRequestCPU,
							corev1.ResourceMemory: s.ACMEOptions.HTTP01SolverResourceRequestMemory,
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    s.ACMEOptions.HTTP01SolverResourceLimitsCPU,
							corev1.ResourceMemory: s.ACMEOptions.HTTP01SolverResourceLimitsMemory,
						},
					},
					Ports: []corev1.ContainerPort{
						{
							Name:          "http",
							ContainerPort: acmeSolverListenPort,
						},
					},
				},
			},
		},
	}
}
