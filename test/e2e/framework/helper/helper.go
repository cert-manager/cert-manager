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

package helper

import (
	"k8s.io/client-go/kubernetes"

	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
)

// Helper provides methods for common operations needed during tests.
type Helper struct {
	cfg *config.Config

	KubeClient kubernetes.Interface
	CMClient   cmclient.Interface
}

func NewHelper(cfg *config.Config) *Helper {
	return &Helper{
		cfg: cfg,
	}
}
