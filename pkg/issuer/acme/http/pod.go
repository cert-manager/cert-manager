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
	"context"
	"fmt"
	"hash/adler32"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

func podLabels(ch *v1alpha1.Challenge) map[string]string {
	domainHash := fmt.Sprintf("%d", adler32.Checksum([]byte(ch.Spec.DNSName)))
	tokenHash := fmt.Sprintf("%d", adler32.Checksum([]byte(ch.Spec.Token)))
	solverIdent := "true"
	return map[string]string{
		// TODO: we need to support domains longer than 63 characters
		// this value should probably be hashed, and then the full plain text
		// value stored as an annotation to make it easier for users to read
		// see #425 for details: https://github.com/jetstack/cert-manager/issues/425
		domainLabelKey:               domainHash,
		tokenLabelKey:                tokenHash,
		solverIdentificationLabelKey: solverIdent,
	}
}

func (s *Solver) ensurePod(ctx context.Context, ch *v1alpha1.Challenge) (*corev1.Pod, error) {
	log := logf.FromContext(ctx).WithName("ensurePod")

	log.V(logf.DebugLevel).Info("checking for existing HTTP01 solver pods")
	existingPods, err := s.getPodsForChallenge(ctx, ch)
	if err != nil {
		return nil, err
	}
	if len(existingPods) == 1 {
		logf.WithRelatedResource(log, existingPods[0]).Info("found one existing HTTP01 solver pod")
		return existingPods[0], nil
	}
	if len(existingPods) > 1 {
		log.Info("multiple challenge solver pods found for challenge. cleaning up all existing pods.")
		err := s.cleanupPods(ctx, ch)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("multiple existing challenge solver pods found and cleaned up. retrying challenge sync")
	}

	log.Info("creating HTTP01 challenge solver pod")

	return s.createPod(ch)
}

// getPodsForChallenge returns a list of pods that were created to solve
// the given challenge
func (s *Solver) getPodsForChallenge(ctx context.Context, ch *v1alpha1.Challenge) ([]*corev1.Pod, error) {
	log := logf.FromContext(ctx)

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
			logf.WithRelatedResource(log, pod).Info("found existing solver pod for this challenge resource, however " +
				"it does not have an appropriate OwnerReference referencing this challenge. Skipping it altogether.")
			continue
		}
		relevantPods = append(relevantPods, pod)
	}

	return relevantPods, nil
}

func (s *Solver) cleanupPods(ctx context.Context, ch *v1alpha1.Challenge) error {
	log := logf.FromContext(ctx, "cleanupPods")

	pods, err := s.getPodsForChallenge(ctx, ch)
	if err != nil {
		return err
	}
	var errs []error
	for _, pod := range pods {
		log := logf.WithRelatedResource(log, pod).V(logf.DebugLevel)
		log.Info("deleting pod resource")

		err := s.Client.CoreV1().Pods(pod.Namespace).Delete(pod.Name, nil)
		if err != nil {
			log.Info("failed to delete pod resource", "error", err)
			errs = append(errs, err)
			continue
		}
		log.Info("successfully deleted pod resource")
	}

	return utilerrors.NewAggregate(errs)
}

// createPod will create a challenge solving pod for the given certificate,
// domain, token and key.
func (s *Solver) createPod(ch *v1alpha1.Challenge) (*corev1.Pod, error) {
	return s.Client.CoreV1().Pods(ch.Namespace).Create(
		s.buildPod(ch))
}

// buildPod will build a challenge solving pod for the given certificate,
// domain, token and key. It will not create it in the API server
func (s *Solver) buildPod(ch *v1alpha1.Challenge) *corev1.Pod {
	pod := s.buildDefaultPod(ch)

	// Override defaults if they have changed in the pod template.
	if ch.Spec.Solver != nil &&
		ch.Spec.Solver.HTTP01 != nil &&
		ch.Spec.Solver.HTTP01.Ingress != nil {
		pod = s.mergePodObjectMetaWithPodTemplate(pod,
			ch.Spec.Solver.HTTP01.Ingress.PodTemplate)
	}

	return pod
}

func (s *Solver) buildDefaultPod(ch *v1alpha1.Challenge) *corev1.Pod {
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

// Merge object meta from the pod template. Fall back to default values.
func (s *Solver) mergePodObjectMetaWithPodTemplate(pod *corev1.Pod, podTempl *v1alpha1.ACMEChallengeSolverHTTP01IngressPodTemplate) *corev1.Pod {
	if podTempl == nil {
		return pod
	}

	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}

	for k, v := range podTempl.Labels {
		pod.Labels[k] = v
	}

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	for k, v := range podTempl.Annotations {
		pod.Annotations[k] = v
	}

	if pod.Spec.NodeSelector == nil {
		pod.Spec.NodeSelector = make(map[string]string)
	}

	for k, v := range podTempl.Spec.NodeSelector {
		pod.Spec.NodeSelector[k] = v
	}

	if pod.Spec.Tolerations == nil {
		pod.Spec.Tolerations = []corev1.Toleration{}
	}

	for _, t := range podTempl.Spec.Tolerations {
		pod.Spec.Tolerations = append(pod.Spec.Tolerations, t)
	}

	if podTempl.Spec.Affinity != nil {
		pod.Spec.Affinity = podTempl.Spec.Affinity
	}

	return pod
}
