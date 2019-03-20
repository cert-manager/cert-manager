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
	"flag"
	"os"
	"time"

	"github.com/openshift/generic-admission-server/pkg/cmd"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/validation/webhooks"
)

var certHook cmd.ValidatingAdmissionHook = &webhooks.CertificateAdmissionHook{}
var issuerHook cmd.ValidatingAdmissionHook = &webhooks.IssuerAdmissionHook{}
var clusterIssuerHook cmd.ValidatingAdmissionHook = &webhooks.ClusterIssuerAdmissionHook{}

func main() {
	// Avoid "logging before flag.Parse" errors from glog
	flag.CommandLine.Parse([]string{})

	// parse the command line flags to pull out the tls-cert-file
	// argument. This flag will be parsed by code inside cmd.RunAdmissionServer
	// so no need to pass it through the call stack or have nice errors
	tlsflagSet := flag.NewFlagSet("tls", flag.ContinueOnError)
	tlsflagVal := tlsflagSet.String("tls-cert-file", "", "")
	tlsflagSet.Parse(os.Args[1:])
	if *tlsflagVal != "" {
		runfilewatch(*tlsflagVal)
	}

	cmd.RunAdmissionServer(
		certHook,
		issuerHook,
		clusterIssuerHook,
	)
}

func runfilewatch(filename string) {
	info, err := os.Stat(filename)
	if err != nil {
		// missing TLS cert file will get turned into a proper error later
		return
	}
	modtime := info.ModTime()
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			info, err := os.Stat(filename)
			if err != nil {
				continue
			}
			if info.ModTime().After(modtime) {
				// let the k8s scheduler restart us
				// TODO(dmo): figure out if there's a way to do this with clean
				// shutdown
				klog.Info("Detected change in TLS certificate %s. Restarting to pick up new certificate", filename)
				os.Exit(0)
			}
		}
	}()
}
