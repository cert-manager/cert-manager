/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/pflag"

	cainjcmd "github.com/jetstack/cert-manager/cmd/cainjector/cmd"
	controllercmd "github.com/jetstack/cert-manager/cmd/controller/cmd"
	ctlcmd "github.com/jetstack/cert-manager/cmd/ctl/cmd"
)

func main() {
	args := os.Args
	if len(args) != 2 {
		must(errors.New("expecting single output directory argument"))
	}

	// remove all global flags that are imported in
	pflag.CommandLine = nil

	root, err := homedir.Expand(args[1])
	must(err)

	must(ensureDirectory(root))

	for _, c := range []*cobra.Command{
		cainjcmd.NewCommandStartInjectorController(nil, nil, nil),
		controllercmd.NewCommandStartCertManagerController(nil),
		ctlcmd.NewCertManagerCtlCommand(nil, nil, nil, nil),
	} {
		dir := filepath.Join(root, c.Use)
		must(ensureDirectory(dir))
		must(doc.GenMarkdownTree(c, dir))
	}
}

func ensureDirectory(dir string) error {
	s, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.Mkdir(dir, os.FileMode(0755))
		}
		return err
	}

	if !s.IsDir() {
		return fmt.Errorf("path it not directory: %s", dir)
	}

	return nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
