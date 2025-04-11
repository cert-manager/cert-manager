/*
Copyright 2020 The cert-manager Authors.

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
	"k8s.io/utils/ptr"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func podLabels(ch *cmacme.Challenge) map[string]string {
	domainHash := fmt.Sprintf("%d", adler32.Checksum([]byte(ch.Spec.DNSName)))
	tokenHash := fmt.Sprintf("%d", adler32.Checksum([]byte(ch.Spec.Token)))
	solverIdent := "true"
	return map[string]string{
		// TODO: we need to support domains longer than 63 characters
		// this value should probably be hashed, and then the full plain text
		// value stored as an annotation to make it easier for users to read
		// see #425 for details: https://github.com/cert-manager/cert-manager/issues/425
		cmacme.DomainLabelKey:               domainHash,
		cmacme.TokenLabelKey:                tokenHash,
		cmacme.SolverIdentificationLabelKey: solverIdent,
	}
}

func (s *Solver) ensurePod(ctx context.Context, ch *cmacme.Challenge) error {
	log := logf.FromContext(ctx).WithName("ensurePod")

	log.V(logf.DebugLevel).Info("checking for existing HTTP01 solver pods")
	existingPods, err := s.getPodsForChallenge(ctx, ch)
	if err != nil {
		return err
	}
	if len(existingPods) == 1 {
		logf.WithRelatedResource(log, existingPods[0]).Info("found one existing HTTP01 solver pod")
		return nil
	}
	if len(existingPods) > 1 {
		log.V(logf.InfoLevel).Info("multiple challenge solver pods found for challenge. cleaning up all existing pods.")
		err := s.cleanupPods(ctx, ch)
		if err != nil {
			return err
		}
		return fmt.Errorf("multiple existing challenge solver pods found and cleaned up. retrying challenge sync")
	}

	log.V(logf.InfoLevel).Info("creating HTTP01 challenge solver pod")

	_, err = s.createPod(ctx, ch)
	return err
}

// getPodsForChallenge returns a list of pods that were created to solve
// the given challenge
func (s *Solver) getPodsForChallenge(ctx context.Context, ch *cmacme.Challenge) ([]*metav1.PartialObjectMetadata, error) {
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

	podMetadataList, err := s.podLister.ByNamespace(ch.Namespace).List(orderSelector)
	if err != nil {
		return nil, err
	}

	var relevantPods []*metav1.PartialObjectMetadata
	for _, pod := range podMetadataList {
		p, ok := pod.(*metav1.PartialObjectMetadata)
		if !ok {
			return nil, fmt.Errorf("internal error: cannot cast PartialMetadata: %+#v", pod)
		}
		if !metav1.IsControlledBy(p, ch) {
			logf.WithRelatedResource(log, p).Info("found existing solver pod for this challenge resource, however " +
				"it does not have an appropriate OwnerReference referencing this challenge. Skipping it altogether.")
			continue
		}
		relevantPods = append(relevantPods, p)
	}

	return relevantPods, nil
}

func (s *Solver) cleanupPods(ctx context.Context, ch *cmacme.Challenge) error {
	log := logf.FromContext(ctx, "cleanupPods")

	pods, err := s.getPodsForChallenge(ctx, ch)
	if err != nil {
		return fmt.Errorf("error retrieving pods for cleanup: %w", err)
	}
	var errs []error
	for _, pod := range pods {
		log := logf.WithRelatedResource(log, pod).V(logf.DebugLevel)
		log.V(logf.InfoLevel).Info("deleting pod resource")

		err := s.Client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
		if err != nil {
			log.V(logf.WarnLevel).Info("failed to delete pod resource", "error", err)
			errs = append(errs, fmt.Errorf("error deleting pod: %w", err))
			continue
		}
		log.V(logf.InfoLevel).Info("successfully deleted pod resource")
	}

	return utilerrors.NewAggregate(errs)
}

// createPod will create a challenge solving pod for the given certificate,
// domain, token and key.
func (s *Solver) createPod(ctx context.Context, ch *cmacme.Challenge) (*corev1.Pod, error) {
	return s.Client.CoreV1().Pods(ch.Namespace).Create(
		ctx,
		s.buildPod(ch),
		metav1.CreateOptions{})
}

// buildPod will build a challenge solving pod for the given certificate,
// domain, token and key. It will not create it in the API server
func (s *Solver) buildPod(ch *cmacme.Challenge) *corev1.Pod {
	pod := s.buildDefaultPod(ch)

	// Override defaults if they have changed in the pod template.
	if ch.Spec.Solver.HTTP01 != nil {
		if ch.Spec.Solver.HTTP01.Ingress != nil {
			pod = s.mergePodObjectMetaWithPodTemplate(pod,
				ch.Spec.Solver.HTTP01.Ingress.PodTemplate)
		}
		if ch.Spec.Solver.HTTP01.GatewayHTTPRoute != nil {
			pod = s.mergePodObjectMetaWithPodTemplate(pod,
				ch.Spec.Solver.HTTP01.GatewayHTTPRoute.PodTemplate)
		}
	}

	return pod
}

// Note: this function builds pod spec using defaults and any configuration
// options passed via flags to cert-manager controller.
// Solver pod configuration via flags is a now deprecated
// mechanism - please use pod template instead when adding any new
// configuration options
// https://github.com/cert-manager/cert-manager/blob/f1d7c432763100c3fb6eb6a1654d29060b479b3c/pkg/apis/acme/v1/types_issuer.go#L270
func (s *Solver) buildDefaultPod(ch *cmacme.Challenge) *corev1.Pod {
	podLabels := podLabels(ch)

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cm-acme-http-solver-",
			Namespace:    ch.Namespace,
			Labels:       podLabels,
			Annotations: map[string]string{
				"sidecar.istio.io/inject":                        "false",
				"cluster-autoscaler.kubernetes.io/safe-to-evict": "true",
			},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ch, challengeGvk)},
		},
		Spec: corev1.PodSpec{
			// The HTTP01 solver process does not need access to the
			// Kubernetes API server, so we turn off automounting of
			// the Kubernetes ServiceAccount token.
			// See https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting
			AutomountServiceAccountToken: ptr.To(false),
			NodeSelector: map[string]string{
				"kubernetes.io/os": "linux",
			},
			RestartPolicy:      corev1.RestartPolicyOnFailure,
			EnableServiceLinks: ptr.To(false),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: ptr.To(s.ACMEOptions.ACMEHTTP01SolverRunAsNonRoot),
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			Containers: []corev1.Container{
				{
					Name:            "acmesolver",
					Image:           s.ACMEOptions.HTTP01SolverImage,
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
					SecurityContext: &corev1.SecurityContext{
						ReadOnlyRootFilesystem:   ptr.To(true),
						AllowPrivilegeEscalation: ptr.To(false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
					},
				},
			},
		},
	}
}

// Merge object meta from the pod template. Fall back to default values.
func (s *Solver) mergePodObjectMetaWithPodTemplate(pod *corev1.Pod, podTempl *cmacme.ACMEChallengeSolverHTTP01IngressPodTemplate) *corev1.Pod {
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

	pod.Spec.Tolerations = append(pod.Spec.Tolerations, podTempl.Spec.Tolerations...)

	if podTempl.Spec.Affinity != nil {
		pod.Spec.Affinity = podTempl.Spec.Affinity
	}

	if podTempl.Spec.PriorityClassName != "" {
		pod.Spec.PriorityClassName = podTempl.Spec.PriorityClassName
	}

	if podTempl.Spec.ServiceAccountName != "" {
		pod.Spec.ServiceAccountName = podTempl.Spec.ServiceAccountName
	}

	if pod.Spec.ImagePullSecrets == nil {
		pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{}
	}

	pod.Spec.ImagePullSecrets = append(pod.Spec.ImagePullSecrets, podTempl.Spec.ImagePullSecrets...)

	if podTempl.Spec.SecurityContext != nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
		pod.Spec.SecurityContext.SELinuxOptions = podTempl.Spec.SecurityContext.SELinuxOptions
		pod.Spec.SecurityContext.RunAsUser = podTempl.Spec.SecurityContext.RunAsUser
		pod.Spec.SecurityContext.RunAsGroup = podTempl.Spec.SecurityContext.RunAsGroup
		pod.Spec.SecurityContext.RunAsNonRoot = podTempl.Spec.SecurityContext.RunAsNonRoot
		pod.Spec.SecurityContext.SupplementalGroups = podTempl.Spec.SecurityContext.SupplementalGroups
		pod.Spec.SecurityContext.FSGroup = podTempl.Spec.SecurityContext.FSGroup
		pod.Spec.SecurityContext.Sysctls = podTempl.Spec.SecurityContext.Sysctls
		pod.Spec.SecurityContext.FSGroupChangePolicy = podTempl.Spec.SecurityContext.FSGroupChangePolicy
		pod.Spec.SecurityContext.SeccompProfile = podTempl.Spec.SecurityContext.SeccompProfile
	}

	return pod
}
