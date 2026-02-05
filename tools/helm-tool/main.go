/*
Copyright 2026 The cert-manager Authors.
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/cert-manager/cert-manager/tools/helm-tool/baker"
	"github.com/spf13/cobra"
)

var (
	imagePathsFile      string
	enterpriseRegistry  string
	enterpriseNamespace string
	allowEU             bool
	fips                bool
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = cobra.Command{
	Use:   "helm-tool",
	Short: "cert-manager Helm chart tools",
}

var imagesCmd = cobra.Command{
	Use:   "images",
	Short: "image-related helpers",
}

var imagesExtractCmd = cobra.Command{
	Use:  "extract",
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		inputPath := args[0]
		images, err := baker.Extract(context.TODO(), inputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not extract: %s\n", err)
			os.Exit(1)
		}
		imagePaths := make([]string, 0, len(images))
		for imagePath := range images {
			imagePaths = append(imagePaths, imagePath)
		}
		slices.Sort(imagePaths)
		if imagePathsFile == "" {
			if err := json.NewEncoder(os.Stdout).Encode(imagePaths); err != nil {
				fmt.Fprintf(os.Stderr, "Could not print found images: %s\n", err)
				os.Exit(1)
			}
			return
		}
		if err := writeJSONFile(imagePathsFile, imagePaths); err != nil {
			fmt.Fprintf(os.Stderr, "Could not write --paths file: %s\n", err)
			os.Exit(1)
		}
	},
}

var imagesBakeCmd = cobra.Command{
	Use:  "bake",
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		inputPath := args[0]
		outputPath := inputPath
		if len(args) == 2 {
			outputPath = args[1]
		}
		if len(imagePathsFile) == 0 {
			fmt.Fprintf(os.Stderr, "--paths flag not provided.\n")
			os.Exit(1)
		}
		paths, err := readPathsFile(imagePathsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not read --paths file: %s\n", err)
			os.Exit(1)
		}
		bakeOutputPath, cleanup, err := TempOutputPath(outputPath, inputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not prepare output: %s\n", err)
			os.Exit(1)
		}
		if cleanup != nil {
			defer cleanup()
		}
		workInput := inputPath
		if enterpriseRegistry != "" || enterpriseNamespace != "" || fips {
			enterpriseOutput, enterpriseCleanup, err := TempOutputPath("", workInput)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Could not prepare enterprise output: %s\n", err)
				os.Exit(1)
			}
			if enterpriseCleanup != nil {
				defer enterpriseCleanup()
			}
			opts := baker.EnterpriseOptions{
				Registry:  enterpriseRegistry,
				Namespace: enterpriseNamespace,
				FIPS:      fips,
				AllowEU:   allowEU,
			}
			if err := baker.RewriteEnterpriseImages(workInput, enterpriseOutput, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not rewrite enterprise images: %s\n", err)
				os.Exit(1)
			}
			workInput = enterpriseOutput
		}
		actions, err := baker.Bake(context.TODO(), workInput, bakeOutputPath, paths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not bake: %s\n", err)
			os.Exit(1)
		}
		if err := replaceOutputPath(bakeOutputPath, outputPath); err != nil {
			fmt.Fprintf(os.Stderr, "Could not write output: %s\n", err)
			os.Exit(1)
		}
		for path, action := range actions {
			fmt.Fprintf(os.Stderr, "%s: %s -> %s\n", path, action.In, action.Out)
		}
	},
}

func init() {
	rootCmd.AddCommand(&imagesCmd)
	imagesCmd.AddCommand(&imagesExtractCmd)
	imagesCmd.AddCommand(&imagesBakeCmd)
	imagesExtractCmd.PersistentFlags().StringVarP(&imagePathsFile, "paths", "p", "", "file containing paths of image._defaultReference in values.yaml (used as check)")
	imagesBakeCmd.PersistentFlags().StringVarP(&imagePathsFile, "paths", "p", "", "file containing paths of image._defaultReference in values.yaml (used as check)")
	imagesBakeCmd.PersistentFlags().StringVar(&enterpriseRegistry, "enterprise-registry", "", "set imageRegistry to an enterprise registry")
	imagesBakeCmd.PersistentFlags().StringVar(&enterpriseNamespace, "enterprise-namespace", "", "set imageNamespace to an enterprise namespace")
	imagesBakeCmd.PersistentFlags().BoolVar(&allowEU, "allow-eu", false, "allow venafi.eu registries (guard until the EU registry exists)")
	imagesBakeCmd.PersistentFlags().BoolVar(&fips, "fips", false, "append -fips to all image.name values")
}

func readPathsFile(path string) ([]string, error) {
	jsonBlob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	imagePaths := []string{}
	if err := json.Unmarshal(jsonBlob, &imagePaths); err != nil {
		return nil, err
	}
	return imagePaths, nil
}

func writeJSONFile(path string, payload any) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func TempOutputPath(outputPath string, inputPath string) (string, func(), error) {
	if outputPath != "" && outputPath != inputPath {
		return outputPath, nil, nil
	}
	baseDir := filepath.Dir(inputPath)
	tempFile, err := os.CreateTemp(baseDir, "helm-tool-*.tmp")
	if err != nil {
		return "", nil, err
	}
	path := tempFile.Name()
	if err := tempFile.Close(); err != nil {
		return "", nil, err
	}
	cleanup := func() {
		_ = os.Remove(path)
	}
	return path, cleanup, nil
}

func replaceOutputPath(tempPath string, outputPath string) error {
	if tempPath == outputPath {
		return nil
	}
	if outputPath == "" {
		return errors.New("output path is empty")
	}
	return os.Rename(tempPath, outputPath)
}
