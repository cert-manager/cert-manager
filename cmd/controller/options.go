package main

import "github.com/spf13/pflag"

type ControllerOptions struct {
	APIServerHost string
	Namespace     string
}

func (o *ControllerOptions) Validate() error {
	return nil
}

func (s *ControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.APIServerHost, "master", "", ""+
		"Optional apiserver host address to connect to. If not specified, autoconfiguration "+
		"will be attempted.")
	fs.StringVar(&s.Namespace, "namespace", "", ""+
		"Optional namespace to monitor resources within. THis can be used to limit the scope "+
		"of cert-manager to a single namespace. If not specified, all namespaces will be watched")
}
