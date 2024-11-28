/*
Copyright 2024 The cert-manager Authors.

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

package issuerlib

import (
	"context"
	"fmt"

	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/globals"
	"github.com/cert-manager/cert-manager/pkg/issuer"
)

const (
	ControllerName = "issuerlib"
)

type Signer struct {
	// issuerFactory is used to obtain a reference to the Issuer implementation
	// for each ClusterIssuer resource
	issuerFactory issuer.Factory
}

func (s Signer) SetupWithManager(ctx context.Context, cctx *controllerpkg.Context, mgr ctrl.Manager) error {
	// instantiate additional helpers used by this controller
	s.issuerFactory = issuer.NewFactory(cctx)

	cl := mgr.GetClient()
	eventRecorder := mgr.GetEventRecorderFor("issuer.cert-manager.io")

	clock := clock.RealClock{}

	secretListener := &ct{
		kubeSharedInformerFactory: cctx.KubeSharedInformerFactory,
		issuerLister:              cctx.SharedInformerFactory.Certmanager().V1().Issuers().Lister(),
	}

	for _, issuerType := range []v1alpha1.Issuer{&cmapi.Issuer{}, &cmapi.ClusterIssuer{}} {
		if err := (&controllers.IssuerReconciler[struct{}]{
			ForObject:   issuerType,
			EventSource: controllers.NewEventStore(),

			FieldOwner: "issuer.cert-manager.io",

			Client:        cl,
			Setup:         s.Setup,
			Check:         s.Check,
			EventRecorder: eventRecorder,
			Clock:         clock,

			PostSetupWithManager: func(ctx context.Context, gvk schema.GroupVersionKind, manager ctrl.Manager, controller controller.Controller) error {
				switch gvk {
				case cmapi.SchemeGroupVersion.WithKind("Issuer"):
					return controller.Watch(secretListener)
				case cmapi.SchemeGroupVersion.WithKind("ClusterIssuer"):
					return controller.Watch(secretListener)
				}
				return fmt.Errorf("GVK %v unexpected", gvk)
			},
		}).SetupWithManager(ctx, mgr); err != nil {
			return fmt.Errorf("%T: %w", issuerType, err)
		}
	}

	return nil
}

func (c Signer) Setup(ctx context.Context, issuerObject v1alpha1.Issuer) (struct{}, error) {
	ctx, cancel := context.WithTimeout(ctx, globals.DefaultControllerContextTimeout)
	defer cancel()

	genericIssuer := issuerObject.(cmapi.GenericIssuer)

	i, err := c.issuerFactory.IssuerFor(genericIssuer)
	if err != nil {
		return struct{}{}, err
	}

	return struct{}{}, i.Setup(ctx, genericIssuer)
}

func (c Signer) Check(ctx context.Context, setupResult struct{}, _ v1alpha1.Issuer) error {
	return nil
}

func init() {
	controllerpkg.Register(ControllerName, func(contextFactory *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		controllerctx, err := contextFactory.Build(ControllerName)
		if err != nil {
			return nil, err
		}

		mgr, err := ctrl.NewManager(controllerctx.RESTConfig, ctrl.Options{
			LeaderElection: false,

			Scheme: controllerctx.Scheme,

			BaseContext: func() context.Context {
				return controllerctx.RootContext
			},
		})
		if err != nil {
			return nil, err
		}

		signer := Signer{}
		if err := signer.SetupWithManager(controllerctx.RootContext, controllerctx, mgr); err != nil {
			return nil, err
		}

		return &controllerWrapper{
			mgr: mgr,
		}, nil
	})
}

type controllerWrapper struct {
	mgr ctrl.Manager
}

var _ controllerpkg.Interface = &controllerWrapper{}

func (c *controllerWrapper) Run(_ int, ctx context.Context) error {
	return c.mgr.Start(ctx)
}
