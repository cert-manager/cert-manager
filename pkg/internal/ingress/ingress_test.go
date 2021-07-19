/*
Copyright 2021 The cert-manager Authors.

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

package ingress

import (
	"context"
	fakediscovery "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/validation/plugins/fake"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/jetstack/cert-manager/pkg/controller"
)

func TestNewLister(t *testing.T) {
	e := envtest.Environment{}
	cfg, err := e.Start()
	assert.NoError(t, err, "Couldn't start envtest environment")
	defer e.Stop()
	client, err := kubernetes.NewForConfig(cfg)
	assert.NoError(t, err, "Couldn't get envtest kubeconfig")

	ctx := &controller.Context{
		RootContext: context.TODO(),
		StopCh:      nil,
		RESTConfig:  nil,
		Client:      client,
		CMClient:    nil,
		GWClient:    nil,
		Recorder:    nil,
		Discovery: fakediscovery.NewDiscovery().WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
			if groupVersion == networkingv1.SchemeGroupVersion.String() {
				return &metav1.APIResourceList{
					TypeMeta:     metav1.TypeMeta{},
					GroupVersion: networkingv1.SchemeGroupVersion.String(),
					APIResources: []metav1.APIResource{
						{
							Name:               "Ingresses",
							SingularName:       "Ingress",
							Namespaced:         true,
							Group:              networkingv1.GroupName,
							Version:            networkingv1.SchemeGroupVersion.Version,
							Kind:               networkingv1.SchemeGroupVersion.WithKind("Ingress").Kind,
							Verbs:              metav1.Verbs{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"},
							ShortNames:         []string{"ing"},
							Categories:         []string{"all"},
							StorageVersionHash: "testing",
						},
					},
				}, nil
			} else {
				return &metav1.APIResourceList{}, nil
			}
		}),
		KubeSharedInformerFactory: informers.NewSharedInformerFactory(client, 10*time.Hour),
		SharedInformerFactory:     nil,
		GWShared:                  nil,
		Namespace:                 "",
		Clock:                     clock.RealClock{},
		Metrics:                   nil,
		IssuerOptions:             controller.IssuerOptions{},
		ACMEOptions:               controller.ACMEOptions{},
		IngressShimOptions:        controller.IngressShimOptions{},
		CertificateOptions:        controller.CertificateOptions{},
		SchedulerOptions:          controller.SchedulerOptions{},
	}

	_, _, err = NewListerInformer(ctx)
	assert.NoError(t, err, "New should not fail")
}
