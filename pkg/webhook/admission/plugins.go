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

package admission

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// Plugins manages initialising, registering and executing admission plugins
// for both validation and mutation.
type Plugins struct {
	decoder runtime.Decoder

	pluginFactory map[string]Factory
}

func NewPlugins(scheme *runtime.Scheme) *Plugins {
	return &Plugins{
		decoder:       serializer.NewCodecFactory(scheme).UniversalDecoder(),
		pluginFactory: make(map[string]Factory),
	}
}

func (ps *Plugins) Register(name string, factory Factory) {
	ps.pluginFactory[name] = factory
}

func (ps *Plugins) NewFromPlugins(names []string, pluginInitializer PluginInitializer) (Interface, error) {
	var plugins []Interface
	for _, pluginName := range names {
		plugin, err := ps.InitPlugin(pluginName, pluginInitializer)
		if err != nil {
			return nil, err
		}
		plugins = append(plugins, plugin)
	}
	return PluginChain(plugins), nil
}

func (ps *Plugins) getPlugin(name string) (Interface, bool, error) {
	f, ok := ps.pluginFactory[name]
	if !ok {
		return nil, false, nil
	}

	plugin, err := f()
	return plugin, true, err
}

func (ps *Plugins) InitPlugin(name string, pluginInitializer PluginInitializer) (Interface, error) {
	plugin, found, err := ps.getPlugin(name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("No plugin named %q registered", name)
	}

	pluginInitializer.Initialize(plugin)
	if err := ValidateInitialization(plugin); err != nil {
		return nil, err
	}

	return plugin, nil
}

// ValidateInitialization will call the InitializationValidate function in each plugin if they implement
// the InitializationValidator interface.
func ValidateInitialization(plugin Interface) error {
	if validater, ok := plugin.(InitializationValidator); ok {
		err := validater.ValidateInitialization()
		if err != nil {
			return err
		}
	}
	return nil
}
