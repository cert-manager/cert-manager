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

package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	config "github.com/cert-manager/cert-manager/internal/apis/config/cainjector"
	cmscheme "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/scheme"
	"github.com/cert-manager/cert-manager/pkg/controller/cainjector"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/profiling"
)

const (
	// This is intended to mitigate "slowloris" attacks by limiting the time a
	// deliberately slow client can spend sending HTTP headers.
	// This default value is copied from:
	// * kubernetes api-server:
	//   https://github.com/kubernetes/kubernetes/blob/9e028b40b9e970142191259effe796b3dab39828/staging/src/k8s.io/apiserver/pkg/server/secure_serving.go#L165-L173
	// * controller-runtime:
	//   https://github.com/kubernetes-sigs/controller-runtime/blob/1ea2be573f7887a9fbd766e9a921c5af344da6eb/pkg/internal/httpserver/server.go#L14
	defaultReadHeaderTimeout = 32 * time.Second
)

func Run(opts *config.CAInjectorConfiguration, ctx context.Context) error {
	log := logf.FromContext(ctx)

	var defaultNamespaces map[string]cache.Config
	if opts.Namespace != "" {
		// If a namespace has been provided, only watch resources in that namespace
		defaultNamespaces = map[string]cache.Config{
			opts.Namespace: {},
		}
	}

	scheme := runtime.NewScheme()
	kscheme.AddToScheme(scheme)
	cmscheme.AddToScheme(scheme)
	apiext.AddToScheme(scheme)
	apireg.AddToScheme(scheme)

	mgr, err := ctrl.NewManager(
		util.RestConfigWithUserAgent(ctrl.GetConfigOrDie(), "cainjector"),
		ctrl.Options{
			Scheme: scheme,
			Cache: cache.Options{
				ReaderFailOnMissingInformer: true,
				DefaultNamespaces:           defaultNamespaces,
			},
			LeaderElection:                opts.LeaderElectionConfig.Enabled,
			LeaderElectionNamespace:       opts.LeaderElectionConfig.Namespace,
			LeaderElectionID:              "cert-manager-cainjector-leader-election",
			LeaderElectionReleaseOnCancel: true,
			LeaderElectionResourceLock:    resourcelock.LeasesResourceLock,
			LeaseDuration:                 &opts.LeaderElectionConfig.LeaseDuration,
			RenewDeadline:                 &opts.LeaderElectionConfig.RenewDeadline,
			RetryPeriod:                   &opts.LeaderElectionConfig.RetryPeriod,
			Metrics:                       metricsserver.Options{BindAddress: "0"},
		})
	if err != nil {
		return fmt.Errorf("error creating manager: %v", err)
	}

	// if a PprofAddr is provided, start the pprof listener
	if opts.EnablePprof {
		pprofListener, err := net.Listen("tcp", opts.PprofAddress)
		if err != nil {
			return err
		}

		profilerMux := http.NewServeMux()
		// Add pprof endpoints to this mux
		profiling.Install(profilerMux)
		log.V(logf.InfoLevel).Info("running go profiler on", "address", opts.PprofAddress)
		server := &http.Server{
			Handler:           profilerMux,
			ReadHeaderTimeout: defaultReadHeaderTimeout, // Mitigation for G112: Potential slowloris attack
		}

		mgr.Add(runnableNoLeaderElectionFunc(func(ctx context.Context) error {
			<-ctx.Done()

			// allow a timeout for graceful shutdown
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// nolint: contextcheck
			return server.Shutdown(shutdownCtx)
		}))

		mgr.Add(runnableNoLeaderElectionFunc(func(ctx context.Context) error {
			if err := server.Serve(pprofListener); err != http.ErrServerClosed {
				return err
			}
			return nil
		}))
	}

	// If cainjector has been configured to watch Certificate CRDs (true by default)
	// (--enable-certificates-data-source=true), poll kubeapiserver for 5 minutes or till
	// certificate CRD is found.
	if opts.EnableDataSourceConfig.Certificates {
		directClient, err := client.New(mgr.GetConfig(), client.Options{
			Scheme: mgr.GetScheme(),
			Mapper: mgr.GetRESTMapper(),
		})
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}
		err = wait.PollUntilContextTimeout(ctx, time.Second, time.Minute*5, true, func(ctx context.Context) (bool, error) {
			certsCRDName := types.NamespacedName{Name: "certificates.cert-manager.io"}
			certsCRD := apiext.CustomResourceDefinition{}
			err := directClient.Get(ctx, certsCRDName, &certsCRD)
			if apierrors.IsNotFound(err) {
				log.Info("cainjector has been configured to watch certificates, but certificates.cert-manager.io CRD not found, retrying with a backoff...")
				return false, nil
			} else if err != nil {
				log.Error(err, "error checking if certificates.cert-manager.io CRD is installed")
				return false, err
			}
			log.V(logf.DebugLevel).Info("certificates.cert-manager.io CRD found")
			return true, nil
		})
		if err != nil {
			log.Error(err, "error retrieving certificate.cert-manager.io CRDs")
			return err
		}
	}

	setupOptions := cainjector.SetupOptions{
		Namespace:                    opts.Namespace,
		EnableCertificatesDataSource: opts.EnableDataSourceConfig.Certificates,
		EnabledReconcilersFor: map[string]bool{
			cainjector.MutatingWebhookConfigurationName:   opts.EnableInjectableConfig.MutatingWebhookConfigurations,
			cainjector.ValidatingWebhookConfigurationName: opts.EnableInjectableConfig.ValidatingWebhookConfigurations,
			cainjector.APIServiceName:                     opts.EnableInjectableConfig.APIServices,
			cainjector.CustomResourceDefinitionName:       opts.EnableInjectableConfig.CustomResourceDefinitions,
		},
	}

	err = cainjector.RegisterAllInjectors(ctx, mgr, setupOptions)
	if err != nil {
		log.Error(err, "failed to register controllers")
		return err
	}

	if err = mgr.Start(ctx); err != nil {
		return fmt.Errorf("error running manager: %v", err)
	}

	return nil
}

type runnableNoLeaderElectionFunc func(context.Context) error

func (r runnableNoLeaderElectionFunc) Start(ctx context.Context) error {
	return r(ctx)
}

func (runnableNoLeaderElectionFunc) NeedLeaderElection() bool {
	// By default, a runnable in c/r is leader election aware.
	// Since we need to run this runnable for all replicas, this runnable must NOT be leader election aware.
	return false
}

var _ manager.Runnable = runnableNoLeaderElectionFunc(nil)

var _ manager.LeaderElectionRunnable = runnableNoLeaderElectionFunc(nil)
