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

// +k8s:deepcopy-gen=package
// +groupName=ctl.cert-manager.io

// Package cert-managerctl is the package that contains the libraries that
// drive the cert-managerctl binary. cert-managerctl is responsible for
// performing ad hock operations on cert-manager resources in Kubernetes
// clusters.
package certmanagerctl
