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

package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/klog"
	apireg "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"

	certmgrscheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	"github.com/jetstack/cert-manager/pkg/controller/cainjector"
	"github.com/jetstack/cert-manager/pkg/util"
)

var scheme = runtime.NewScheme()

func init() {
	kscheme.AddToScheme(scheme)
	certmgrscheme.AddToScheme(scheme)
	apireg.AddToScheme(scheme)
}

type InjectorControllerOptions struct {
	Namespace               string
	LeaderElect             bool
	LeaderElectionNamespace string
	LeaderElectionID        string

	StdOut io.Writer
	StdErr io.Writer
}

func (o *InjectorControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Namespace, "namespace", "", ""+
		"If set, this limits the scope of cainjector to a single namespace. "+
		"If set, cainjector will not update resources with certificates outside of the "+
		"configured namespace.")
	fs.BoolVar(&o.LeaderElect, "leader-elect", true, ""+
		"If true, cainjector will perform leader election between instances to ensure no more "+
		"than one instance of cainjector operates at a time")
	fs.StringVar(&o.LeaderElectionNamespace, "leader-election-namespace", "", ""+
		"Namespace used to perform leader election (defaults to controller's namespace). "+
		"Only used if leader election is enabled")
	fs.StringVar(&o.LeaderElectionID, "leader-election-id", "", ""+
		"Override the identifier to use in leader election.  Only used if leader election is enabled")
}

func NewInjectorControllerOptions(out, errOut io.Writer) *InjectorControllerOptions {
	o := &InjectorControllerOptions{
		StdOut: out,
		StdErr: errOut,
	}

	return o
}

// NewCommandStartInjectorController is a CLI handler for starting cert-manager
func NewCommandStartInjectorController(out, errOut io.Writer, stopCh <-chan struct{}) *cobra.Command {
	o := NewInjectorControllerOptions(out, errOut)

	cmd := &cobra.Command{
		Use:   "ca-injector",
		Short: fmt.Sprintf("CA Injection Controller for Kubernetes (%s) (%s)", util.AppVersion, util.AppGitCommit),
		Long: `
cert-manager CA injector is a Kubernetes addon to automate the injection of CA data into
webhooks and APIServices from cert-manager certificates.

It will ensure that annotated webhooks and API services always have the correct
CA data from the referenced certificates, which can then be used to serve API
servers and webhook servers.`,

		// TODO: Refactor this function from this package
		Run: func(cmd *cobra.Command, args []string) {
			klog.Infof("starting ca-injector %s (revision %s)", util.AppVersion, util.AppGitCommit)
			o.RunInjectorController(stopCh)
		},
	}

	flags := cmd.Flags()
	o.AddFlags(flags)

	return cmd
}

func (o InjectorControllerOptions) RunInjectorController(stopCh <-chan struct{}) {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Namespace:               o.Namespace,
		LeaderElection:          o.LeaderElect,
		LeaderElectionNamespace: o.LeaderElectionNamespace,
		LeaderElectionID:        o.LeaderElectionID,
	})

	if err != nil {
		klog.Fatalf("error creating manager: %v", err)
	}

	// TODO(directxman12): enabled controllers for separate injectors?
	if err := cainjector.RegisterAll(mgr); err != nil {
		klog.Fatalf("error registering controllers: %v", err)
	}

	if err := mgr.Start(stopCh); err != nil {
		klog.Fatalf("error running manager: %v", err)
	}
}
