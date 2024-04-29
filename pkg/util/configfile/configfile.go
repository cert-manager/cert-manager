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

package configfile

import (
	"fmt"
	"os"
	"path/filepath"
)

type configurationFSLoader struct {
	readFileFunc func(filename string) ([]byte, error)
	filename     string
}

type ConfigFile interface {
	DecodeAndConfigure([]byte) error
	GetPathRefs() ([]*string, error)
}

func (f *configurationFSLoader) Load(config ConfigFile) error {
	data, err := f.readFileFunc(f.filename)
	if err != nil {
		return fmt.Errorf("failed to read config file %q, error: %v", f.filename, err)
	}

	if len(data) == 0 {
		return fmt.Errorf("config file %q was empty", f.filename)
	}

	if err := config.DecodeAndConfigure(data); err != nil {
		return err
	}

	// make all paths absolute
	if paths, err := config.GetPathRefs(); err != nil {
		return err
	} else {
		resolveRelativePaths(paths, filepath.Dir(f.filename))
	}

	return nil
}

func NewConfigurationFSLoader(readFileFunc func(filename string) ([]byte, error), filename string) (*configurationFSLoader, error) {
	var f func(string) ([]byte, error)

	// Default the readfile function to use os.Readfile for convenience.
	if readFileFunc == nil {
		f = os.ReadFile
	} else {
		f = readFileFunc
	}

	return &configurationFSLoader{
		readFileFunc: f,
		filename:     filename,
	}, nil
}

func resolveRelativePaths(paths []*string, root string) {
	for _, path := range paths {
		// leave empty paths alone, "no path" is a valid input
		// do not attempt to resolve paths that are already absolute
		if len(*path) > 0 && !filepath.IsAbs(*path) {
			*path = filepath.Join(root, *path)
		}
	}
}
