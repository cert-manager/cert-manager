package http

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/ingress/core/pkg/ingress/annotations/class"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer/acme/http/solver"
	"github.com/jetstack-experimental/cert-manager/pkg/log"
	"github.com/jetstack-experimental/cert-manager/pkg/util"
)

const (
	// HTTP01Timeout is the max amount of time to wait for an HTTP01 challenge
	// to succeed
	HTTP01Timeout = time.Minute * 15
	// acmeSolverListenPort is the port acmesolver should listen on
	acmeSolverListenPort = 8089
	// acmeSolverImage is the docker image containing acmesolver to use
	acmeSolverImage = "quay.io/jetstack/cert-manager-acmesolver:canary.2"
)

// svcNameFunc returns the name for the service to solve the challenge
func svcNameFunc(crtName, domain string) string {
	return dns1035(fmt.Sprintf("cm-%s-%s", crtName, domain))
}

// ingNameFunc returns the name for the ingress to solve the challenge
func ingNameFunc(crtName, domain string) string {
	return dns1035(fmt.Sprintf("cm-%s-%s", crtName, domain))
}

func jobNameFunc(crtName, domain string) string {
	return dns1035(fmt.Sprintf("cm-%s-%s", crtName, domain))
}

// Solver is an implementation of the acme http-01 challenge solver protocol
type Solver struct {
	issuer       *v1alpha1.Issuer
	client       kubernetes.Interface
	secretLister corev1listers.SecretLister
}

// NewSolver returns a new ACME HTTP01 solver for the given Issuer and client.
func NewSolver(issuer *v1alpha1.Issuer, client kubernetes.Interface, secretLister corev1listers.SecretLister) *Solver {
	return &Solver{issuer, client, secretLister}
}

// labelsForCert returns some labels to add to resources related to the given
// Certificate.
// TODO: move this somewhere 'general', so that other control loops can filter
// their watches based on these labels and save watching *all* resource types.
func labelsForCert(crt *v1alpha1.Certificate, domain string) map[string]string {
	return map[string]string{
		"certmanager.k8s.io/managed":     "true",
		"certmanager.k8s.io/domain":      domain,
		"certmanager.k8s.io/certificate": crt.Name,
		"certmanager.k8s.io/id":          util.RandStringRunes(5),
	}
}

func dns1035(s string) string {
	return strings.Replace(s, ".", "-", -1)
}

// ensureService will ensure the service required to solve this challenge
// exists in the target API server, either by updating the existing Service
// or by creating a new one.
func (s *Solver) ensureService(crt *v1alpha1.Certificate, domain string, labels map[string]string) (svc *corev1.Service, err error) {
	svcName := svcNameFunc(crt.Name, domain)
	svc, err = s.client.CoreV1().Services(crt.Namespace).Get(svcName, metav1.GetOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return nil, fmt.Errorf("error checking for existing service when ensuring service: %s", err.Error())
	}
	if svc == nil {
		svc = &corev1.Service{}
	}

	svc.Name = dns1035(fmt.Sprintf("cm-%s-%s", crt.Name, domain))
	svc.Namespace = crt.Namespace
	if svc.Labels == nil {
		svc.Labels = make(map[string]string)
	}
	for k, v := range labels {
		svc.Labels[k] = v
	}

	svcPort := &corev1.ServicePort{}
	svcPort.Name = "http"
	svcPort.Port = acmeSolverListenPort
	svcPort.TargetPort = intstr.FromInt(acmeSolverListenPort)

	exists := false
	for i, p := range svc.Spec.Ports {
		if p.Port == acmeSolverListenPort {
			svc.Spec.Ports[i] = *svcPort
			exists = true
			break
		}
	}
	if !exists {
		svc.Spec.Ports = append(svc.Spec.Ports, *svcPort)
	}

	svc.Spec.Type = corev1.ServiceTypeNodePort
	svc.Spec.Selector = labels

	return util.EnsureService(s.client, svc)
}

// cleanupService will ensure the service created for this challenge request
// does not exist.
func (s *Solver) cleanupService(crt *v1alpha1.Certificate, domain string) error {
	svcName := svcNameFunc(crt.Name, domain)
	err := s.client.CoreV1().Services(crt.Namespace).Delete(svcName, nil)
	if err != nil && !k8sErrors.IsNotFound(err) {
		return fmt.Errorf("error cleaning up service: %s", err.Error())
	}
	return nil
}

// ensureIngress will ensure the ingress required to solve this challenge
// exists.
func (s *Solver) ensureIngress(crt *v1alpha1.Certificate, svcName, domain, token string, labels map[string]string) (ing *extv1beta1.Ingress, err error) {
	domainCfg := crt.Spec.ACME.ConfigForDomain(domain)
	if existingIngressName := domainCfg.HTTP01.Ingress; existingIngressName != "" {
		ing, err = s.ensureIngressHasRule(existingIngressName, crt, svcName, domain, token, nil)
	} else {
		ingName := ingNameFunc(crt.Name, domain)
		ing, err = s.ensureIngressHasRule(ingName, crt, svcName, domain, token, labels)
	}

	if err != nil {
		return nil, err
	}

	return util.EnsureIngress(s.client, ing)
}

// cleanupIngress will remove the rules added by cert-manager to an existing
// ingress, or delete the ingress if an existing ingress name is not specified
// on the certificate.
func (s *Solver) cleanupIngress(crt *v1alpha1.Certificate, svcName, domain, token string, labels map[string]string) error {
	domainCfg := crt.Spec.ACME.ConfigForDomain(domain)
	existingIngressName := domainCfg.HTTP01.Ingress

	if existingIngressName == "" {
		ingName := ingNameFunc(crt.Name, domain)
		err := s.client.ExtensionsV1beta1().Ingresses(crt.Namespace).Delete(ingName, nil)
		if err != nil && !k8sErrors.IsNotFound(err) {
			return fmt.Errorf("error cleaning up ingress: %s", err.Error())
		}
		return nil
	}

	ing, err := s.client.ExtensionsV1beta1().Ingresses(crt.Namespace).Get(existingIngressName, metav1.GetOptions{})

	if err != nil && !k8sErrors.IsNotFound(err) {
		return fmt.Errorf("error cleaning up ingress: %s", err.Error())
	}

	ingPathToDel := ingressPath(token, svcName)
Outer:
	for _, rule := range ing.Spec.Rules {
		if rule.Host == domain {
			if rule.HTTP == nil {
				return nil
			}
			for i, path := range rule.HTTP.Paths {
				if path.Path == ingPathToDel.Path {
					rule.HTTP.Paths = append(rule.HTTP.Paths[:i], rule.HTTP.Paths[i+1:]...)
					break Outer
				}
			}
		}
	}

	_, err = s.client.ExtensionsV1beta1().Ingresses(ing.Namespace).Update(ing)

	if err != nil {
		return fmt.Errorf("error cleaning up ingress: %s", err.Error())
	}

	return nil
}

// ensureIngressHasRule will return an Ingress resource that contains the rule
// required to solve the ACME challenge request for the given domain. If an
// ingress named `ingName` already exists, it will be updated to contain the
// required rule and returned. Otherwise, a new Ingress resource is returned.
func (s *Solver) ensureIngressHasRule(ingName string, crt *v1alpha1.Certificate, svcName, domain, token string, labels map[string]string) (ing *extv1beta1.Ingress, err error) {
	domainCfg := crt.Spec.ACME.ConfigForDomain(domain)
	ing, err = s.client.ExtensionsV1beta1().Ingresses(crt.Namespace).Get(ingName, metav1.GetOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return nil, fmt.Errorf("error checking for existing ingress when ensuring ingress: %s", err.Error())
	}
	if ing == nil {
		ing = &extv1beta1.Ingress{}
	}

	ing.Name = ingName
	ing.Namespace = crt.Namespace
	if ing.Annotations == nil {
		ing.Annotations = make(map[string]string)
	}
	if domainCfg.HTTP01.IngressClass != nil {
		ing.Annotations[class.IngressKey] = *domainCfg.HTTP01.IngressClass
	}
	if ing.Labels == nil {
		ing.Labels = make(map[string]string)
	}
	for k, v := range labels {
		ing.Labels[k] = v
	}

	ingPathToAdd := ingressPath(token, svcName)

	for i, rule := range ing.Spec.Rules {
		if rule.Host == domain {
			http := rule.HTTP
			if http == nil {
				http = &extv1beta1.HTTPIngressRuleValue{}
				ing.Spec.Rules[i].HTTP = http
			}
			http.Paths = append(http.Paths, ingPathToAdd)
			return ing, nil
		}
	}

	ing.Spec.Rules = append(ing.Spec.Rules, extv1beta1.IngressRule{
		Host: domain,
		IngressRuleValue: extv1beta1.IngressRuleValue{
			HTTP: &extv1beta1.HTTPIngressRuleValue{
				Paths: []extv1beta1.HTTPIngressPath{ingPathToAdd},
			},
		},
	})

	return ing, nil
}

// ingressPath returns the ingress HTTPIngressPath object needed to solve this
// challenge.
func ingressPath(token, serviceName string) extv1beta1.HTTPIngressPath {
	return extv1beta1.HTTPIngressPath{
		Path: fmt.Sprintf("%s/%s", solver.HTTPChallengePath, token),
		Backend: extv1beta1.IngressBackend{
			ServiceName: serviceName,
			ServicePort: intstr.FromInt(acmeSolverListenPort),
		},
	}
}

// ensureJob will ensure the job required to solve this challenge exists in the
// Kubernetes API server.
func (s *Solver) ensureJob(crt *v1alpha1.Certificate, domain, token, key string, labels map[string]string) (*batchv1.Job, error) {
	activeDeadlineSeconds := int64(HTTP01Timeout / time.Second)
	jobName := jobNameFunc(crt.Name, domain)

	err := s.client.BatchV1().Jobs(crt.Namespace).Delete(jobName, nil)
	if err != nil && !k8sErrors.IsNotFound(err) {
		return nil, fmt.Errorf("error removing old job when creating new job resource: %s", err.Error())
	}

	return s.client.BatchV1().Jobs(crt.Namespace).Create(&batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: crt.Namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			ActiveDeadlineSeconds: &activeDeadlineSeconds,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyOnFailure,
					Containers: []corev1.Container{
						{
							Name: "acmesolver",
							// TODO: use an image as specified as a config option
							Image:           acmeSolverImage,
							ImagePullPolicy: corev1.PullAlways,
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
									corev1.ResourceMemory: resource.MustParse("2Mi"),
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
			},
		},
	})
}

func (s *Solver) cleanupJob(crt *v1alpha1.Certificate, domain string) error {
	jobName := jobNameFunc(crt.Name, domain)

	propPolicy := metav1.DeletePropagationBackground
	err := s.client.BatchV1().Jobs(crt.Namespace).Delete(jobName, &metav1.DeleteOptions{
		PropagationPolicy: &propPolicy,
	})

	if err != nil && !k8sErrors.IsNotFound(err) {
		return fmt.Errorf("error cleaning up job '%s': %s", jobName, err.Error())
	}
	return nil
}

// Present will create the required service, update/create the required ingress
// and created a Kubernetes Job to solve the HTTP01 challenge
func (s *Solver) Present(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error {
	labels := labelsForCert(crt, domain)

	svc, err := s.ensureService(crt, domain, labels)

	if err != nil {
		return fmt.Errorf("error ensuring http01 challenge service: %s", err.Error())
	}

	_, err = s.ensureIngress(crt, svc.Name, domain, token, labels)

	if err != nil {
		return fmt.Errorf("error ensuring http01 challenge ingress: %s", err.Error())
	}

	_, err = s.ensureJob(crt, domain, token, key, labels)

	if err != nil {
		return fmt.Errorf("error ensuring http01 challenge job: %s", err.Error())
	}

	return nil
}

// Wait will continuously test if the ingress controller has updated it's
// routes to include the HTTP01 challenge path, or return with an error if the
// context deadline is exceeded.
func (s *Solver) Wait(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error {
	ctx, cancel := context.WithTimeout(ctx, HTTP01Timeout)
	defer cancel()
	for {
		select {
		case err := <-func() <-chan error {
			out := make(chan error, 1)
			go func() {
				defer close(out)
				out <- testReachability(ctx, domain, fmt.Sprintf("%s/%s", solver.HTTPChallengePath, token), key)
			}()
			return out
		}():
			if err != nil {
				log.Printf("[%s] Error self checking HTTP01 challenge: %s", domain, err.Error())
				time.Sleep(time.Second * 5)
				continue
			}
			log.Printf("[%s] HTTP01 challenge self checking passed", domain)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

}

// testReachability will attempt to connect to the 'domain' with 'path' and
// check if the returned body equals 'key'
func testReachability(ctx context.Context, domain, path, key string) error {
	url := &url.URL{}
	url.Scheme = "http"
	url.Host = domain
	url.Path = path

	response, err := http.Get(url.String())
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("wrong status code '%d'", response.StatusCode)
	}

	defer response.Body.Close()
	presentedKey, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return errors.New("unable to read body")
	}

	if string(presentedKey) != key {
		if err != nil {
			return fmt.Errorf("presented key (%s) did not match expected (%s)", presentedKey, key)
		}
	}

	return nil
}

// CleanUp will ensure the created service and ingress are clean/deleted of any
// cert-manager created data.
func (s *Solver) CleanUp(ctx context.Context, crt *v1alpha1.Certificate, domain, token, key string) error {
	if err := s.cleanupJob(crt, domain); err != nil {
		return fmt.Errorf("[%s] Error cleaning up job: %s", domain, err.Error())
	}
	if err := s.cleanupService(crt, domain); err != nil {
		return fmt.Errorf("[%s] Error cleaning up service: %s", domain, err.Error())
	}
	if err := s.cleanupIngress(crt, svcNameFunc(crt.Name, domain), domain, token, labelsForCert(crt, domain)); err != nil {
		return fmt.Errorf("[%s] Error cleaning up ingress: %s", domain, err.Error())
	}

	return nil
}
