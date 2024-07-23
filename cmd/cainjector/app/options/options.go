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

package options

import (
	"flag"
	"strings"

	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	config "github.com/cert-manager/cert-manager/internal/apis/config/cainjector"
	configscheme "github.com/cert-manager/cert-manager/internal/apis/config/cainjector/scheme"
	configv1alpha1 "github.com/cert-manager/cert-manager/pkg/apis/config/cainjector/v1alpha1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

// CAInjectorFlags defines options that can only be configured via flags.
type CAInjectorFlags struct {
	// Path to a file containing a CAInjectorConfiguration resource
	Config string
}

func NewCAInjectorFlags() *CAInjectorFlags {
	return &CAInjectorFlags{}
}

func (f *CAInjectorFlags) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&f.Config, "config", "", "Path to a file containing a CAInjectorConfiguration object used to configure the controller")
}

func NewCAInjectorConfiguration() (*config.CAInjectorConfiguration, error) {
	scheme, _, err := configscheme.NewSchemeAndCodecs()
	if err != nil {
		return nil, err
	}
	versioned := &configv1alpha1.CAInjectorConfiguration{}
	scheme.Default(versioned)
	config := &config.CAInjectorConfiguration{}
	if err := scheme.Convert(versioned, config, nil); err != nil {
		return nil, err
	}
	return config, nil
}

func AddConfigFlags(fs *pflag.FlagSet, c *config.CAInjectorConfiguration) {
	fs.StringVar(&c.KubeConfig, "kubeconfig", c.KubeConfig, ""+
		"Paths to a kubeconfig. Only required if out-of-cluster.")
	fs.StringVar(&c.Namespace, "namespace", c.Namespace, ""+
		"If set, this limits the scope of cainjector to a single namespace. "+
		"If set, cainjector will not update resources with certificates outside of the "+
		"configured namespace.")
	fs.BoolVar(&c.LeaderElectionConfig.Enabled, "leader-elect", c.LeaderElectionConfig.Enabled, ""+
		"If true, cainjector will perform leader election between instances to ensure no more "+
		"than one instance of cainjector operates at a time")
	fs.StringVar(&c.LeaderElectionConfig.Namespace, "leader-election-namespace", c.LeaderElectionConfig.Namespace, ""+
		"Namespace used to perform leader election. Only used if leader election is enabled")
	fs.DurationVar(&c.LeaderElectionConfig.LeaseDuration, "leader-election-lease-duration", c.LeaderElectionConfig.LeaseDuration, ""+
		"The duration that non-leader candidates will wait after observing a leadership "+
		"renewal until attempting to acquire leadership of a led but unrenewed leader "+
		"slot. This is effectively the maximum duration that a leader can be stopped "+
		"before it is replaced by another candidate. This is only applicable if leader "+
		"election is enabled.")
	fs.DurationVar(&c.LeaderElectionConfig.RenewDeadline, "leader-election-renew-deadline", c.LeaderElectionConfig.RenewDeadline, ""+
		"The interval between attempts by the acting master to renew a leadership slot "+
		"before it stops leading. This must be less than or equal to the lease duration. "+
		"This is only applicable if leader election is enabled.")
	fs.DurationVar(&c.LeaderElectionConfig.RetryPeriod, "leader-election-retry-period", c.LeaderElectionConfig.RetryPeriod, ""+
		"The duration the clients should wait between attempting acquisition and renewal "+
		"of a leadership. This is only applicable if leader election is enabled.")

	fs.BoolVar(&c.EnableDataSourceConfig.Certificates, "enable-certificates-data-source", c.EnableDataSourceConfig.Certificates, ""+
		"Enable configuring cert-manager.io Certificate resources as potential sources for CA data. "+
		"Requires cert-manager.io Certificate CRD to be installed. This data source can be disabled "+
		"to reduce memory consumption if you only use cainjector as part of cert-manager's installation")
	fs.BoolVar(&c.EnableInjectableConfig.ValidatingWebhookConfigurations, "enable-validatingwebhookconfigurations-injectable", c.EnableInjectableConfig.ValidatingWebhookConfigurations, ""+
		"Inject CA data to annotated ValidatingWebhookConfigurations. This functionality is required "+
		"for cainjector to correctly function as cert-manager's internal component")
	fs.BoolVar(&c.EnableInjectableConfig.MutatingWebhookConfigurations, "enable-mutatingwebhookconfigurations-injectable", c.EnableInjectableConfig.MutatingWebhookConfigurations, ""+
		"Inject CA data to annotated MutatingWebhookConfigurations. This functionality is required for "+
		"cainjector to work correctly as cert-manager's internal component")
	fs.BoolVar(&c.EnableInjectableConfig.CustomResourceDefinitions, "enable-customresourcedefinitions-injectable", c.EnableInjectableConfig.CustomResourceDefinitions, ""+
		"Inject CA data to annotated CustomResourceDefinitions. This functionality is not required if "+
		"cainjecor is only used as cert-manager's internal component and setting it to false might slightly reduce memory consumption")
	fs.BoolVar(&c.EnableInjectableConfig.APIServices, "enable-apiservices-injectable", c.EnableInjectableConfig.APIServices, ""+
		"Inject CA data to annotated APIServices. This functionality is not required if cainjector is "+
		"only used as cert-manager's internal component and setting it to false might reduce memory consumption")

	fs.BoolVar(&c.EnablePprof, "enable-profiling", c.EnablePprof, ""+
		"Enable profiling for controller.")
	fs.StringVar(&c.PprofAddress, "profiler-address", c.PprofAddress,
		"The host and port that Go profiler should listen on, i.e localhost:6060. Ensure that profiler is not exposed on a public address. Profiler will be served at /debug/pprof.")

	fs.Var(cliflag.NewMapStringBool(&c.FeatureGates), "feature-gates", "A set of key=value pairs that describe feature gates for alpha/experimental features. "+
		"Options are:\n"+strings.Join(utilfeature.DefaultFeatureGate.KnownFeatures(), "\n"))

	logf.AddFlags(&c.Logging, fs)

	fs.StringVar(&c.MetricsListenAddress, "metrics-listen-address", c.MetricsListenAddress, "The host and port that the metrics endpoint should listen on. The value '0' disables the metrics server")
	fs.StringVar(&c.MetricsTLSConfig.Filesystem.CertFile, "metrics-tls-cert-file", c.MetricsTLSConfig.Filesystem.CertFile, "path to the file containing the TLS certificate to serve metrics with")
	fs.StringVar(&c.MetricsTLSConfig.Filesystem.KeyFile, "metrics-tls-private-key-file", c.MetricsTLSConfig.Filesystem.KeyFile, "path to the file containing the TLS private key to serve metrics with")

	fs.DurationVar(&c.MetricsTLSConfig.Dynamic.LeafDuration, "metrics-dynamic-serving-leaf-duration", c.MetricsTLSConfig.Dynamic.LeafDuration, "leaf duration of metrics serving certificates")
	fs.StringVar(&c.MetricsTLSConfig.Dynamic.SecretNamespace, "metrics-dynamic-serving-ca-secret-namespace", c.MetricsTLSConfig.Dynamic.SecretNamespace, "namespace of the secret used to store the CA that signs metrics serving certificates")
	fs.StringVar(&c.MetricsTLSConfig.Dynamic.SecretName, "metrics-dynamic-serving-ca-secret-name", c.MetricsTLSConfig.Dynamic.SecretName, "name of the secret used to store the CA that signs serving certificates")
	fs.StringSliceVar(&c.MetricsTLSConfig.Dynamic.DNSNames, "metrics-dynamic-serving-dns-names", c.MetricsTLSConfig.Dynamic.DNSNames, "DNS names that should be present on certificates generated by the metrics dynamic serving CA")

	tlsCipherPossibleValues := cliflag.TLSCipherPossibleValues()
	fs.StringSliceVar(&c.MetricsTLSConfig.CipherSuites, "metrics-tls-cipher-suites", c.MetricsTLSConfig.CipherSuites,
		"Comma-separated list of cipher suites for the metrics server. "+
			"If omitted, the default Go cipher suites will be used.  "+
			"Possible values: "+strings.Join(tlsCipherPossibleValues, ","))
	tlsPossibleVersions := cliflag.TLSPossibleVersions()
	fs.StringVar(&c.MetricsTLSConfig.MinTLSVersion, "metrics-tls-min-version", c.MetricsTLSConfig.MinTLSVersion,
		"Minimum TLS version supported by the metrics server. If omitted, the default Go minimum version will be used. "+
			"Possible values: "+strings.Join(tlsPossibleVersions, ", "))

	// The controller-runtime flag (--kubeconfig) that we need
	// relies on the "flag" package but we use "spf13/pflag".
	var controllerRuntimeFlags flag.FlagSet
	ctrlconfig.RegisterFlags(&controllerRuntimeFlags)
	controllerRuntimeFlags.VisitAll(func(f *flag.Flag) {
		fs.AddGoFlag(f)
	})
}
