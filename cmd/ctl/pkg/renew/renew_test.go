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

package renew

import (
	"context"
	"testing"

	"k8s.io/cli-runtime/pkg/genericclioptions"
)

type stringFlag struct {
	name, value string
}

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		options        *Options
		args           []string
		setStringFlags []stringFlag
		expErr         bool
	}{
		"If there are arguments, as well as label selector, error": {
			options: &Options{
				LabelSelector: "foo=bar",
			},
			args:   []string{"abc"},
			expErr: true,
		},
		"If there are all certificates selected, as well as label selector, error": {
			options: &Options{
				LabelSelector: "foo=bar",
				All:           true,
			},
			args:   []string{""},
			expErr: true,
		},
		"If there are all certificates selected, as well as arguments, error": {
			options: &Options{
				All: true,
			},
			args:   []string{"abc"},
			expErr: true,
		},
		"If all certificates in all namespaces selected, don't error": {
			options: &Options{
				All:           true,
				AllNamespaces: true,
			},
			expErr: false,
		},
		"If --namespace and --all namespace specified, error": {
			options: &Options{
				All: true,
			},
			setStringFlags: []stringFlag{
				{name: "namespace", value: "foo"},
			},
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := NewCmdRenew(context.TODO(), genericclioptions.IOStreams{})

			// This is normally registered in the main func. We add here to test
			// against flags normally inherited.
			kubeConfigFlags := genericclioptions.NewConfigFlags(true)
			kubeConfigFlags.AddFlags(cmd.PersistentFlags())

			if test.setStringFlags != nil {
				for _, s := range test.setStringFlags {
					if err := cmd.PersistentFlags().Set(s.name, s.value); err != nil {
						t.Fatal(err)
					}
				}
			}

			err := test.options.Validate(cmd, test.args)
			if test.expErr != (err != nil) {
				t.Errorf("expected error=%t got=%v",
					test.expErr, err)
			}
		})
	}
}
