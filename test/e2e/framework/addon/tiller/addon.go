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

package tiller

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/jetstack/cert-manager/test/e2e/framework/addon/base"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
)

var (
	// all permissions on everything
	tillerClusterRole = rbacv1.ClusterRole{
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"*"},
			},
		},
	}
	tillerDeployment = appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":  "helm",
					"name": "tiller",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":  "helm",
						"name": "tiller",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "tiller-deploy",
							Args: []string{"/tiller", "--listen=localhost:44134"},
							Ports: []corev1.ContainerPort{
								{
									Name:          "tiller",
									ContainerPort: 44134,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("100Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("10m"),
									corev1.ResourceMemory: resource.MustParse("10Mi"),
								},
							},
							LivenessProbe:  buildProbe("/liveness"),
							ReadinessProbe: buildProbe("/readiness"),
						},
					},
				},
			},
		},
	}
)

func buildProbe(path string) *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   path,
				Port:   intstr.FromInt(44135),
				Scheme: corev1.URISchemeHTTP,
			},
		},
		FailureThreshold:    3,
		InitialDelaySeconds: 1,
		PeriodSeconds:       10,
		SuccessThreshold:    1,
		TimeoutSeconds:      1,
	}
}

// Tiller defines an addon that installs an instance of tiller in the target cluster.
type Tiller struct {
	config      *config.Config
	baseDetails *base.Details

	// Base is the base addon to use for Kubernetes API interactions
	Base *base.Base

	// Optional name to use for the tiller deployment.
	// If not specified, 'tiller-deploy' will be used.
	Name string

	// Optional namespace to deploy Tiller into.
	// If not specified, the 'kube-system' namespace will be used.
	Namespace string

	// ImageRepo is the image repo to use for Tiller.
	// If not set, the global tiller image repo set in the config will be used.
	ImageRepo string

	// ImageTag is the image tag to use for Tiller.
	// If not set, the global tiller image tag set in the config will be used.
	ImageTag string

	// ClusterPermissions will cause the addon to give this tiller instance
	// global permissions over the cluster.
	ClusterPermissions bool

	// provisionedDeployment contains a reference to a copy of the instance of
	// tiller that has been deployed.
	// Use of this field must be guarded, as when tiller is deployed as a shared
	// test resource and tests are run in parallel, only one instance of this
	// structure will actually have the field set.
	// We only store this field so that Deprovision can be called after Provision.
	provisionedNamespace          *corev1.Namespace
	provisionedServiceAccount     *corev1.ServiceAccount
	provisionedClusterRole        *rbacv1.ClusterRole
	provisionedClusterRoleBinding *rbacv1.ClusterRoleBinding
	provisionedRoleBinding        *rbacv1.RoleBinding
	provisionedDeployment         *appsv1.Deployment

	createdNs bool
}

// Details return the details about the Tiller instance deployed
type Details struct {
	// Name of the deployment created for Tiller
	Name string

	// Namespace that Tiller has been deployed into
	Namespace string

	// KubeConfig is the path to a kubeconfig file that can be used to speak
	// to the tiller instance
	KubeConfig string

	// KubeContext is the name of the kubeconfig context to use to speak to the
	// tiller instance
	KubeContext string
}

// Setup will configure this addon but not provision it
func (t *Tiller) Setup(c *config.Config) error {
	t.config = c

	if t.Base == nil {
		t.Base = &base.Base{}
		if err := t.Base.Setup(c); err != nil {
			return err
		}
	}
	t.baseDetails = t.Base.Details()

	if t.Name == "" {
		return fmt.Errorf("name of the tiller instance must be specified")
	}

	if t.Namespace == "" {
		return fmt.Errorf("namespace for the tiller instance must be specified")
	}

	if t.ImageRepo == "" {
		t.ImageRepo = t.config.Addons.Tiller.ImageRepo
	}

	if t.ImageTag == "" {
		t.ImageTag = t.config.Addons.Tiller.ImageTag
	}

	return nil
}

// Provision an instance of tiller-deploy
func (t *Tiller) Provision() error {
	var err error

	ns := t.buildNamespace()
	sa := t.buildServiceAccount()
	clusterRole := t.buildClusterRole()
	depl := t.buildDeployment()

	t.provisionedNamespace, err = t.baseDetails.KubeClient.CoreV1().Namespaces().Create(ns)
	t.createdNs = true
	if err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		} else {
			t.createdNs = false
		}
	}

	t.provisionedServiceAccount, err = t.baseDetails.KubeClient.CoreV1().ServiceAccounts(sa.Namespace).Create(sa)
	if err != nil {
		return err
	}

	t.provisionedClusterRole, err = t.baseDetails.KubeClient.RbacV1().ClusterRoles().Create(clusterRole)
	if err != nil {
		return err
	}

	if t.ClusterPermissions {
		crb := t.buildClusterRoleBinding()
		t.provisionedClusterRoleBinding, err = t.baseDetails.KubeClient.RbacV1().ClusterRoleBindings().Create(crb)
		if err != nil {
			return err
		}
	} else {
		rb := t.buildRoleBinding()
		t.provisionedRoleBinding, err = t.baseDetails.KubeClient.RbacV1().RoleBindings(rb.Namespace).Create(rb)
		if err != nil {
			return err
		}
	}

	t.provisionedDeployment, err = t.baseDetails.KubeClient.AppsV1().Deployments(depl.Namespace).Create(depl)
	if err != nil {
		return err
	}

	// otherwise lookup the newly created pods name
	err = t.Base.Details().Helper().WaitForAllPodsRunningInNamespace(t.Namespace)
	if err != nil {
		return err
	}

	return nil
}

// Deprovision the deployed instance of tiller-deploy
func (t *Tiller) Deprovision() error {
	var errs []error

	if t.provisionedDeployment != nil {
		err := t.baseDetails.KubeClient.AppsV1().Deployments(t.provisionedDeployment.Namespace).Delete(t.provisionedDeployment.Name, nil)
		if !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
	}

	if t.provisionedClusterRoleBinding != nil {
		err := t.baseDetails.KubeClient.RbacV1().ClusterRoleBindings().Delete(t.provisionedClusterRoleBinding.Name, nil)
		if !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
	}

	if t.provisionedRoleBinding != nil {
		err := t.baseDetails.KubeClient.RbacV1().RoleBindings(t.provisionedRoleBinding.Namespace).Delete(t.provisionedRoleBinding.Name, nil)
		if !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
	}

	if t.provisionedClusterRole != nil {
		err := t.baseDetails.KubeClient.RbacV1().ClusterRoles().Delete(t.provisionedClusterRole.Name, nil)
		if !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
	}

	if t.provisionedServiceAccount != nil {
		err := t.baseDetails.KubeClient.CoreV1().ServiceAccounts(t.provisionedServiceAccount.Namespace).Delete(t.provisionedServiceAccount.Name, nil)
		if !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
	}

	if t.createdNs {
		// TODO: wait for namespace to be deleted
		err := t.baseDetails.KubeClient.CoreV1().Namespaces().Delete(t.Namespace, nil)
		if !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
	}

	return utilerrors.NewAggregate(errs)
}

// Details must be possible to compute without Provision being called if we want
// to be able to provision global/shared instances of Tiller.
func (t *Tiller) Details() (*Details, error) {
	d := &Details{
		Name:      t.Name,
		Namespace: t.Namespace,
	}

	return d, nil
}

func (t *Tiller) SupportsGlobal() bool {
	return true
}

func (t *Tiller) buildNamespace() *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: t.Namespace,
		},
	}
}

func (t *Tiller) buildServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      t.Name,
			Namespace: t.Namespace,
		},
	}
}

func (t *Tiller) buildClusterRole() *rbacv1.ClusterRole {
	role := tillerClusterRole.DeepCopy()
	role.GenerateName = t.Name
	return role
}

func (t *Tiller) buildRoleBinding() *rbacv1.RoleBinding {
	crb := t.buildClusterRoleBinding()
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      t.Name,
			Namespace: t.Namespace,
		},
		Subjects: crb.Subjects,
		RoleRef:  crb.RoleRef,
	}
}

func (t *Tiller) buildClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: t.Name + "-",
		},
		Subjects: []rbacv1.Subject{
			{
				Name:      t.Name,
				Namespace: t.Namespace,
				Kind:      "ServiceAccount",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     t.provisionedClusterRole.Name,
		},
	}
}

func (t *Tiller) buildDeployment() *appsv1.Deployment {
	depl := tillerDeployment.DeepCopy()

	depl.Name = t.Name
	depl.Namespace = t.Namespace

	// we add the name of the tiller instance as a label to prevent clashes
	// if more than one tiller gets deployed to a single namespace
	depl.Spec.Selector.MatchLabels["tiller-name"] = t.Name
	depl.Spec.Template.ObjectMeta.Labels["tiller-name"] = t.Name

	// Set the image repo and tag
	depl.Spec.Template.Spec.Containers[0].Image = t.config.Addons.Tiller.ImageRepo + ":" + t.config.Addons.Tiller.ImageTag
	depl.Spec.Template.Spec.ServiceAccountName = t.Name
	// TODO: set the TILLER_NAMESPACE environment variable

	return depl
}
