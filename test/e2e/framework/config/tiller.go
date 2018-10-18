package config

import (
	"flag"
	"fmt"
)

type Tiller struct {
	// Tiller image repo to use when deploying
	ImageRepo string

	// Tiller image tag to use when deploying
	ImageTag string
}

func (n *Tiller) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&n.ImageRepo, "tiller-image-repo", "gcr.io/kubernetes-helm/tiller", "docker image repo for tiller-deploy")
	fs.StringVar(&n.ImageTag, "tiller-image-tag", "v2.11.0", "docker image tag for tiller-deploy")
}

func (n *Tiller) Validate() []error {
	var errs []error
	if n.ImageRepo == "" {
		errs = append(errs, fmt.Errorf("--tiller-image-repo must be specified"))
	}
	if n.ImageTag == "" {
		errs = append(errs, fmt.Errorf("--tiller-image-tag must be specified"))
	}
	return errs
}
