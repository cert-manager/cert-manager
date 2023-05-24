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

package factory

import (
	"context"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ValidArgsListCertificates returns a cobra ValidArgsFunction for listing Certificates.
func ValidArgsListCertificates(ctx context.Context, factory **Factory) func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		f := (*factory)
		if err := f.complete(); err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		certList, err := f.CMClient.CertmanagerV1().Certificates(f.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}

		var names []string
		for _, cert := range certList.Items {
			names = append(names, cert.Name)
		}

		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

// ValidArgsListSecrets returns a cobra ValidArgsFunction for listing Secrets.
func ValidArgsListSecrets(ctx context.Context, factory **Factory) func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		f := (*factory)
		if err := f.complete(); err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		secretsList, err := f.KubeClient.CoreV1().Secrets(f.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}

		var names []string
		for _, secret := range secretsList.Items {
			names = append(names, secret.Name)
		}

		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

// ValidArgsListCertificateSigningRequests returns a cobra ValidArgsFunction for
// listing CertificateSigningRequests.
func ValidArgsListCertificateSigningRequests(ctx context.Context, factory **Factory) func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		f := (*factory)
		if err := f.complete(); err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		csrList, err := f.KubeClient.CertificatesV1().CertificateSigningRequests().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}

		var names []string
		for _, csr := range csrList.Items {
			names = append(names, csr.Name)
		}

		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

// ValidArgsListCertificateRequests returns a cobra ValidArgsFunction for listing
// CertificateRequests.
func ValidArgsListCertificateRequests(ctx context.Context, factory **Factory) func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		f := (*factory)
		if err := f.complete(); err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		crList, err := f.CMClient.CertmanagerV1().CertificateRequests(f.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		var names []string
		for _, cr := range crList.Items {
			names = append(names, cr.Name)
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

// validArgsListNamespaces returns a cobra ValidArgsFunction for listing
// namespaces.
func validArgsListNamespaces(ctx context.Context, factory *Factory) func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		if err := factory.complete(); err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		namespaceList, err := factory.KubeClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}

		var names []string
		for _, namespace := range namespaceList.Items {
			names = append(names, namespace.Name)
		}

		return names, cobra.ShellCompDirectiveNoFileComp
	}
}
