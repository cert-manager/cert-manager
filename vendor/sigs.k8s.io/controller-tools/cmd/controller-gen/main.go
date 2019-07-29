/*
Copyright 2018 The Kubernetes Authors.

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
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"sigs.k8s.io/controller-tools/pkg/crd"
	"sigs.k8s.io/controller-tools/pkg/deepcopy"
	"sigs.k8s.io/controller-tools/pkg/genall"
	"sigs.k8s.io/controller-tools/pkg/genall/help"
	prettyhelp "sigs.k8s.io/controller-tools/pkg/genall/help/pretty"
	"sigs.k8s.io/controller-tools/pkg/markers"
	"sigs.k8s.io/controller-tools/pkg/rbac"
	"sigs.k8s.io/controller-tools/pkg/webhook"
)

//go:generate go run ../helpgen/main.go paths=../../pkg/... generate:headerFile=../../boilerplate.go.txt,year=2019

// Options are specified to controller-gen by turning generators and output rules into
// markers, and then parsing them using the standard registry logic (without the "+").
// Each marker and output rule should thus be usable as a marker target.

var (
	// allGenerators maintains the list of all known generators, giving
	// them names for use on the command line.
	// each turns into a command line option,
	// and has options for output forms.
	allGenerators = map[string]genall.Generator{
		"crd":     crd.Generator{},
		"rbac":    rbac.Generator{},
		"object":  deepcopy.Generator{},
		"webhook": webhook.Generator{},
	}

	// allOutputRules defines the list of all known output rules, giving
	// them names for use on the command line.
	// Each output rule turns into two command line options:
	// - output:<generator>:<form> (per-generator output)
	// - output:<form> (default output)
	allOutputRules = map[string]genall.OutputRule{
		"dir":       genall.OutputToDirectory(""),
		"none":      genall.OutputToNothing,
		"stdout":    genall.OutputToStdout,
		"artifacts": genall.OutputArtifacts{},
	}

	// optionsRegistry contains all the marker definitions used to process command line options
	optionsRegistry = &markers.Registry{}
)

func init() {
	for genName, gen := range allGenerators {
		// make the generator options marker itself
		defn := markers.Must(markers.MakeDefinition(genName, markers.DescribesPackage, gen))
		if err := optionsRegistry.Register(defn); err != nil {
			panic(err)
		}
		if helpGiver, hasHelp := gen.(genall.HasHelp); hasHelp {
			if help := helpGiver.Help(); help != nil {
				optionsRegistry.AddHelp(defn, help)
			}
		}

		// make per-generation output rule markers
		for ruleName, rule := range allOutputRules {
			ruleMarker := markers.Must(markers.MakeDefinition(fmt.Sprintf("output:%s:%s", genName, ruleName), markers.DescribesPackage, rule))
			if err := optionsRegistry.Register(ruleMarker); err != nil {
				panic(err)
			}
			if helpGiver, hasHelp := rule.(genall.HasHelp); hasHelp {
				if help := helpGiver.Help(); help != nil {
					optionsRegistry.AddHelp(ruleMarker, help)
				}
			}
		}
	}

	// make "default output" output rule markers
	for ruleName, rule := range allOutputRules {
		ruleMarker := markers.Must(markers.MakeDefinition("output:"+ruleName, markers.DescribesPackage, rule))
		if err := optionsRegistry.Register(ruleMarker); err != nil {
			panic(err)
		}
		if helpGiver, hasHelp := rule.(genall.HasHelp); hasHelp {
			if help := helpGiver.Help(); help != nil {
				optionsRegistry.AddHelp(ruleMarker, help)
			}
		}
	}

	// add in the common options markers
	if err := genall.RegisterOptionsMarkers(optionsRegistry); err != nil {
		panic(err)
	}
}

func main() {
	helpLevel := 0
	whichLevel := 0
	cmd := &cobra.Command{
		Use:   "controller-gen",
		Short: "Generate Kubernetes API extension resources and code.",
		Long:  "Generate Kubernetes API extension resources and code.",
		Example: `	# Generate RBAC manifests and crds for all types under apis/,
	# outputting crds to /tmp/crds and everything else to stdout
	controller-gen rbac:roleName=<role name> crd paths=./apis/... output:crd:dir=/tmp/crds output:stdout

	# Generate deepcopy implementations for a particular file
	controller-gen deepcopy paths=./apis/v1beta1/some_types.go

	# Run all the generators for a given project
	controller-gen paths=./apis/...
`,
		RunE: func(c *cobra.Command, rawOpts []string) error {
			if helpLevel > 0 {
				return c.Usage()
			}
			return runGenerators(c, rawOpts, whichLevel)
		},
	}
	cmd.Flags().CountVarP(&whichLevel, "which-markers", "w", "print out all markers available with the requested generators (passing more times yields more detailed information)")
	cmd.Flags().CountVarP(&helpLevel, "detailed-help", "h", "print out more detailed help (passing more times yields more detailed information about options)")
	cmd.Flags().Bool("help", false, "print out usage and a summary of options")
	oldUsage := cmd.UsageFunc()
	cmd.SetUsageFunc(func(c *cobra.Command) error {
		if err := oldUsage(c); err != nil {
			return err
		}
		if helpLevel == 0 {
			helpLevel = summaryHelp
		}
		fmt.Fprintf(c.OutOrStderr(), "\n\nOptions\n\n")
		return helpForLevels(c.OutOrStdout(), c.OutOrStderr(), helpLevel, optionsRegistry, help.SortByOption)
	})

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runGenerators(c *cobra.Command, rawOptions []string, whichLevel int) error {
	if whichLevel > 0 {
		// just grab a registry so we don't lag while trying to load roots
		// (like we'd do if we just constructed the full runtime).
		reg, err := genall.RegistryFromOptions(optionsRegistry, rawOptions)
		if err != nil {
			return err
		}

		return helpForLevels(c.OutOrStdout(), c.OutOrStderr(), whichLevel, reg, help.SortByCategory)
	}

	rt, err := genall.FromOptions(optionsRegistry, rawOptions)
	if err != nil {
		return err
	}

	if hadErrs := rt.Run(); hadErrs {
		return fmt.Errorf("not all generators ran successfully")
	}

	return nil
}

func helpForLevels(mainOut io.Writer, errOut io.Writer, whichLevel int, reg *markers.Registry, sorter help.SortGroup) error {
	helpInfo := help.ByCategory(reg, sorter)
	switch whichLevel {
	case jsonHelp:
		if err := json.NewEncoder(mainOut).Encode(helpInfo); err != nil {
			return err
		}
	case detailedHelp, fullHelp:
		fullDetail := whichLevel == fullHelp
		for _, cat := range helpInfo {
			if cat.Category == "" {
				continue
			}
			contents := prettyhelp.MarkersDetails(fullDetail, cat.Category, cat.Markers)
			if err := contents.WriteTo(errOut); err != nil {
				return err
			}
		}
	case summaryHelp:
		for _, cat := range helpInfo {
			if cat.Category == "" {
				continue
			}
			contents := prettyhelp.MarkersSummary(cat.Category, cat.Markers)
			if err := contents.WriteTo(errOut); err != nil {
				return err
			}
		}
	}
	return nil
}

const (
	_ = iota
	summaryHelp
	detailedHelp
	fullHelp
	jsonHelp
)
