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

// +k8s:conversion-gen=github.com/cert-manager/cert-manager/internal/apis/certmanager
// +k8s:conversion-gen-external-types=github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1
// +k8s:defaulter-gen=TypeMeta
// +k8s:defaulter-gen-input=github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1

// +groupName=cert-manager.io
package v1
