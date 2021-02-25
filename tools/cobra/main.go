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

	acmesolvercmd "github.com/cert-manager/cert-manager/cmd/acmesolver/app"
	cainjectorapp "github.com/cert-manager/cert-manager/cmd/cainjector/app"
	controllerapp "github.com/cert-manager/cert-manager/cmd/controller/app"
	ctlcmd "github.com/cert-manager/cert-manager/cmd/ctl/cmd"
	webhookcmd "github.com/cert-manager/cert-manager/cmd/webhook/app"
)

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}

func run(args []string) error {
	if len(args) != 2 {
		return errors.New("expecting single output directory argument")
	}

	// remove all global flags that are imported in
	pflag.CommandLine = nil

	root, err := homedir.Expand(args[1])
	if err != nil {
		return err
	}

	if err := ensureDirectory(root); err != nil {
		return err
	}

	for _, c := range []*cobra.Command{
		cainjectorapp.NewCommandStartInjectorController(nil, nil, nil),
		controllerapp.NewCommandStartCertManagerController(nil),
		ctlcmd.NewCertManagerCtlCommand(nil, nil, nil, nil),
		webhookcmd.NewServerCommand(nil),
		acmesolvercmd.NewACMESolverCommand(nil),
	} {
		dir := filepath.Join(root, c.Use)

		if err := ensureDirectory(dir); err != nil {
			return err
		}

		if err := doc.GenMarkdownTree(c, dir); err != nil {
			return err
		}
	}

	return nil
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
