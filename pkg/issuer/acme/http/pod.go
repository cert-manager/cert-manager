package http

import (
	"fmt"
	"hash/adler32"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func podLabels(ch v1alpha1.ACMEOrderChallenge) map[string]string {
	domainHash := fmt.Sprintf("%d", adler32.Checksum([]byte(ch.Domain)))
	tokenHash := fmt.Sprintf("%d", adler32.Checksum([]byte(ch.Token)))
	return map[string]string{
		// TODO: we need to support domains longer than 63 characters
		// this value should probably be hashed, and then the full plain text
		// value stored as an annotation to make it easier for users to read
		// see #425 for details: https://github.com/jetstack/cert-manager/issues/425
		domainLabelKey: domainHash,
		tokenLabelKey:  tokenHash,
	}
}

func (s *Solver) ensurePod(crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) (*corev1.Pod, error) {
	existingPods, err := s.getPodsForChallenge(crt, ch)
	if err != nil {
		return nil, err
	}
	if len(existingPods) == 1 {
		return existingPods[0], nil
	}
	if len(existingPods) > 1 {
		errMsg := fmt.Sprintf("multiple challenge solver pods found for certificate '%s/%s'. Cleaning up existing pods.", crt.Namespace, crt.Name)
		glog.Infof(errMsg)
		err := s.cleanupPods(crt, ch)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(errMsg)
	}

	glog.Infof("No existing HTTP01 challenge solver pod found for Certificate %q. One will be created.", crt.Namespace+"/"+crt.Name)
	return s.createPod(crt, ch)
}

// getPodsForChallenge returns a list of pods that were created to solve
// the given challenge
func (s *Solver) getPodsForChallenge(crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) ([]*corev1.Pod, error) {
	podLabels := podLabels(ch)
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
				"but it is not owned by the Certificate resource, so skipping it.", pod.Namespace+"/"+pod.Name, crt.Namespace+"/"+crt.Name)
			continue
		}
		relevantPods = append(relevantPods, pod)
	}

	return relevantPods, nil
}

func (s *Solver) cleanupPods(crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) error {
	pods, err := s.getPodsForChallenge(crt, ch)
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
func (s *Solver) createPod(crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) (*corev1.Pod, error) {
	return s.Client.CoreV1().Pods(crt.Namespace).Create(s.buildPod(crt, ch))
}

// buildPod will build a challenge solving pod for the given certificate,
// domain, token and key. It will not create it in the API server
func (s *Solver) buildPod(crt *v1alpha1.Certificate, ch v1alpha1.ACMEOrderChallenge) *corev1.Pod {
	podLabels := podLabels(ch)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cm-acme-http-solver-",
			Namespace:    crt.Namespace,
			Labels:       podLabels,
			Annotations: map[string]string{
				"sidecar.istio.io/inject": "false",
			},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyOnFailure,
			Containers: []corev1.Container{
				{
					Name: "acmesolver",
					// TODO: use an image as specified as a config option
					Image:           s.ACMEOptions.HTTP01SolverImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					// TODO: replace this with some kind of cmdline generator
					Args: []string{
						fmt.Sprintf("--listen-port=%d", acmeSolverListenPort),
						fmt.Sprintf("--domain=%s", ch.Domain),
						fmt.Sprintf("--token=%s", ch.Token),
						fmt.Sprintf("--key=%s", ch.Key),
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
