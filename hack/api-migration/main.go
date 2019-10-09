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
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	networkingv1beta "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"

	// This package is required to be imported to register all client
	// plugins.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

const (
	oldGroupName = "certmanager.k8s.io"
)

var (
	kubeconfig string
	origFile   string
	newFile    string
	migrations = map[string]string{
		"certmanager.k8s.io/acme-http01-edit-in-place": "acme.cert-manager.io/http01-edit-in-place",
		"certmanager.k8s.io/acme-http01-ingress-class": "acme.cert-manager.io/http01-ingress-class",

		"certmanager.k8s.io/issuer":           "cert-manager.io/issuer",
		"certmanager.k8s.io/cluster-issuer":   "cert-manager.io/cluster-issuer",
		"certmanager.k8s.io/alt-names":        "cert-manager.io/alt-names",
		"certmanager.k8s.io/ip-sans":          "cert-manager.io/ip-sans",
		"certmanager.k8s.io/common-name":      "cert-manager.io/common-name",
		"certmanager.k8s.io/issuer-name":      "cert-manager.io/issuer-name",
		"certmanager.k8s.io/issuer-kind":      "cert-manager.io/issuer-kind",
		"certmanager.k8s.io/certificate-name": "cert-manager.io/certificate-name",
	}

	deprecations = []string{
		"certmanager.k8s.io/acme-challenge-type",
		"certmanager.k8s.io/acme-dns01-provider",
	}
)

var cmd = &cobra.Command{
	Use:  "cert-manager-api-migration",
	Long: "A tool to download Ingress resources and convert cert-manager annotations from certmanager.k8s.io to cert-manager.io. This tool will not modify resources in the API server.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(kubeconfig) == 0 {
			kubeconfig = os.Getenv("KUBECONFIG")
		}

		if len(kubeconfig) == 0 {
			return errors.New("flag --kubeconfig or environment variable $KUBECONFIG must be set")
		}

		client, err := clientSet(kubeconfig)
		if err != nil {
			return err
		}

		ingList, err := client.ExtensionsV1beta1().Ingresses("").List(metav1.ListOptions{})
		if err != nil {
			return err
		}

		ingStr, err := writeIngressToFile(ingList, origFile)
		if err != nil {
			return err
		}

		fmt.Printf("written current ingresses to file %q\n", origFile)
		fmt.Printf("searching ingress resources for occurrences of old API annotations...\n")

		for oldA, newA := range migrations {
			count := strings.Count(ingStr, oldA)
			if count == 0 {
				continue
			}

			fmt.Printf("found %d instances of %q\tmigrating to %q\n", count, oldA, newA)

			ingStr = strings.ReplaceAll(ingStr, oldA, newA)
		}

		for _, d := range deprecations {
			count := strings.Count(ingStr, d)
			if count == 0 {
				continue
			}

			fmt.Printf("found %d instances of %q\tthis field is DEPRECATED and will be deleted\n", count, d)

			lines := strings.Split(ingStr, "\n")

			for i, line := range lines {
				if strings.Contains(line, d) {
					lines = append(lines[:i], lines[i+1:]...)
				}
			}

			ingStr = strings.Join(lines, "\n")
		}

		count := strings.Count(ingStr, oldGroupName)
		if count > 0 {
			fmt.Fprintf(os.Stderr,
				"found %d more instances of the group %q with unrecognised paths\n", count, oldGroupName)
		}

		if err := ioutil.WriteFile(newFile, []byte(ingStr), 0644); err != nil {
			return err
		}

		fmt.Printf("wrote new ingresses to file %q\n", newFile)

		var buff bytes.Buffer
		diffFile := fmt.Sprintf("%s.%s.diff", origFile, newFile)
		eCmd := exec.Command("diff", origFile, newFile)
		eCmd.Stdout = &buff

		if err := eCmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
				return err
			}
		}

		if err := ioutil.WriteFile(diffFile, buff.Bytes(), 0644); err != nil {
			return err
		}

		fmt.Printf("wrote diff to file %q\n", diffFile)

		fmt.Printf("\nPlease check for any missing or incorrect annotations in your newly generated ingress manifests.\n")
		fmt.Printf("You should now check the diff of the two files to determine what has changed - either by inspecting the diff file %q, or running the command yourself:\n\n",
			diffFile)
		fmt.Printf("$ diff %s %s\n", origFile, newFile)

		return nil
	},
}

func writeIngressToFile(ingList *networkingv1beta.IngressList, path string) (string, error) {
	s := json.NewYAMLSerializer(json.DefaultMetaFactory, scheme.Scheme,
		scheme.Scheme)

	var buff bytes.Buffer

	for _, ing := range ingList.Items {
		ing.Kind = "Ingress"
		ing.APIVersion = "extensions/v1beta1"

		if err := s.Encode(&ing, &buff); err != nil {
			return "", err
		}

		if _, err := buff.WriteString("---\n"); err != nil {
			return "", err
		}
	}

	if err := ioutil.WriteFile(path, buff.Bytes(), 0644); err != nil {
		return "", err
	}

	return buff.String(), nil
}

func main() {
	cmd.PersistentFlags().StringVarP(&kubeconfig, "kubeconfig", "k", "", "Path location to Kubeconfig")
	cmd.PersistentFlags().StringVarP(&origFile, "original-file", "o", "ingress.yaml", "File path to store the current list of Ingress resources")
	cmd.PersistentFlags().StringVarP(&newFile, "new-file", "n", "ingress-migrated.yaml", "File path to store the migrated Ingress resources")

	if err := cmd.Execute(); err != nil {
		fmt.Fprint(os.Stderr, err.Error())
	}
}

func clientSet(kubeconfig string) (*kubernetes.Clientset, error) {
	kubeconfigBytes, err := ioutil.ReadFile(kubeconfig)
	if err != nil {
		return nil, err
	}

	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfigBytes)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}
