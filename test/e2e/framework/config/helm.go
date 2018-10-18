package config

import (
	"flag"
	"fmt"
)

type Helm struct {
	// Path to the Helm binary to use during tests
	Path string
}

func (n *Helm) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&n.Path, "helm-binary-path", "helm", "path to the helm binary to use in tests")
}

func (n *Helm) Validate() []error {
	var errs []error
	if n.Path == "" {
		errs = append(errs, fmt.Errorf("--helm-binary-path must be specified"))
	}
	return errs
}
