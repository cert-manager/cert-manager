package http

import (
	"fmt"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func podLabels(crt *v1alpha1.Certificate, domain string) map[string]string {
	return map[string]string{
		certNameLabelKey: crt.Name,
		// TODO: we need to support domains longer than 63 characters
		// this value should probably be hashed, and then the full plain text
		// value stored as an annotation to make it easier for users to read
		// see #425 for details: https://github.com/jetstack/cert-manager/issues/425
		domainLabelKey: domain,
	}
}

func (s *Solver) ensurePod(crt *v1alpha1.Certificate, domain, token, key string) (*corev1.Pod, error) {
	existingPods, err := s.getPodsForCertificate(crt, domain)
	if err != nil {
		return nil, err
	}
	if len(existingPods) == 1 {
		return existingPods[0], nil
	}
	if len(existingPods) > 1 {
		errMsg := fmt.Sprintf("multiple challenge solver pods found for certificate '%s/%s'. Cleaning up existing pods.", crt.Namespace, crt.Name)
		glog.Infof(errMsg)
		err := s.cleanupPods(crt, domain)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(errMsg)
	}

	glog.Infof("No existing HTTP01 challenge solver pod found for Certificate %q. One will be created.", crt.Name)
	return s.createPod(crt, domain, token, key)
}

// getPodsForCertificate returns a list of pods that were created to solve
// http challenges for the given domain
func (s *Solver) getPodsForCertificate(crt *v1alpha1.Certificate, domain string) ([]*corev1.Pod, error) {
	podLabels := podLabels(crt, domain)
	orderSelector := labels.NewSelector()
	for key, val := range podLabels {
		req, err := labels.NewRequirement(key, selection.Equals, []string{val})
		if err != nil {
			return nil, err
		}
		orderSelector = orderSelector.Add(*req)
	}

	podList, err := s.podLister.Pods(crt.Namespace).List(orderSelector)
	if err != nil {
		return nil, err
	}

	var relevantPods []*corev1.Pod
	for _, pod := range podList {
		if !metav1.IsControlledBy(pod, crt) {
			glog.Infof("Found pod %q with acme-order-url annotation set to that of Certificate %q"+
				"but it is not owned by the Certificate resource, so skipping it.", pod.Name, crt.Name)
			continue
		}
		relevantPods = append(relevantPods, pod)
	}

	return relevantPods, nil
}

func (s *Solver) cleanupPods(crt *v1alpha1.Certificate, domain string) error {
	pods, err := s.getPodsForCertificate(crt, domain)
	if err != nil {
		return err
	}
	var errs []error
	for _, pod := range pods {
		// TODO: should we call DeleteCollection here? We'd need to somehow
		// also ensure ownership as part of that request using a FieldSelector.
		err := s.client.CoreV1().Pods(pod.Namespace).Delete(pod.Name, nil)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return utilerrors.NewAggregate(errs)
}

// createPod will create a challenge solving pod for the given certificate,
// domain, token and key.
func (s *Solver) createPod(crt *v1alpha1.Certificate, domain, token, key string) (*corev1.Pod, error) {
	return s.client.CoreV1().Pods(crt.Namespace).Create(s.buildPod(crt, domain, token, key))
}

// buildPod will build a challenge solving pod for the given certificate,
// domain, token and key. It will not create it in the API server
func (s *Solver) buildPod(crt *v1alpha1.Certificate, domain, token, key string) *corev1.Pod {
	podLabels := podLabels(crt, domain)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    "cm-acme-http-solver-",
			Namespace:       crt.Namespace,
			Labels:          podLabels,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyOnFailure,
			Containers: []corev1.Container{
				{
					Name: "acmesolver",
					// TODO: use an image as specified as a config option
					Image:           s.solverImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					// TODO: replace this with some kind of cmdline generator
					Args: []string{
						fmt.Sprintf("--listen-port=%d", acmeSolverListenPort),
						fmt.Sprintf("--domain=%s", domain),
						fmt.Sprintf("--token=%s", token),
						fmt.Sprintf("--key=%s", key),
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("10m"),
							corev1.ResourceMemory: resource.MustParse("64Mi"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("10m"),
							corev1.ResourceMemory: resource.MustParse("64Mi"),
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
