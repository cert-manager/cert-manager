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

package validation

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	//utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	defaults "github.com/cert-manager/cert-manager/internal/apis/config/controller/v1alpha1"
)

func ValidateControllerConfiguration(o *config.ControllerConfiguration) error {
	if len(o.IngressShimConfig.DefaultIssuerKind) == 0 {
		return errors.New("the --default-issuer-kind flag must not be empty")
	}

	if o.KubernetesAPIBurst <= 0 {
		return fmt.Errorf("invalid value for kube-api-burst: %v must be higher than 0", o.KubernetesAPIBurst)
	}

	if o.KubernetesAPIQPS <= 0 {
		return fmt.Errorf("invalid value for kube-api-qps: %v must be higher than 0", o.KubernetesAPIQPS)
	}

	if float32(o.KubernetesAPIBurst) < o.KubernetesAPIQPS {
		return fmt.Errorf("invalid value for kube-api-burst: %v must be higher or equal to kube-api-qps: %v", o.KubernetesAPIQPS, o.KubernetesAPIQPS)
	}

	for _, server := range o.ACMEHTTP01Config.SolverNameservers {
		// ensure all servers have a port number
		_, _, err := net.SplitHostPort(server)
		if err != nil {
			return fmt.Errorf("invalid DNS server (%v): %v", err, server)
		}
	}

	for _, server := range o.ACMEDNS01Config.RecursiveNameservers {
		// ensure all servers follow one of the following formats:
		// - <ip address>:<port>
		// - https://<DoH RFC 8484 server address>

		if strings.HasPrefix(server, "https://") {
			_, err := url.ParseRequestURI(server)
			if err != nil {
				return fmt.Errorf("invalid DNS server (%v): %v", err, server)
			}
		} else {
			_, _, err := net.SplitHostPort(server)
			if err != nil {
				return fmt.Errorf("invalid DNS server (%v): %v", err, server)
			}
		}
	}

	errs := []error{}
	allControllersSet := sets.NewString(defaults.AllControllers...)
	for _, controller := range o.Controllers {
		if controller == "*" {
			continue
		}

		controller = strings.TrimPrefix(controller, "-")
		if !allControllersSet.Has(controller) {
			errs = append(errs, fmt.Errorf("%q is not in the list of known controllers", controller))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("validation failed for '--controllers': %v", errs)
	}

	return nil
}
