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

package install_framework

import (
	"os"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/cert-manager/cert-manager/test/internal/apiserver"
)

type TestInstallApiServer struct {
	environment *envtest.Environment
	testUser    *envtest.AuthenticatedUser

	kubeClient kubernetes.Interface

	kubeConfig string
}

type CleanupFunction func()

func NewTestInstallApiServer(t *testing.T) (*TestInstallApiServer, CleanupFunction) {
	env, stopFn := apiserver.RunBareControlPlane(t)

	testUser, err := env.ControlPlane.AddUser(
		envtest.User{
			Name:   "test",
			Groups: []string{"system:masters"},
		},
		&rest.Config{
			// gotta go fast during tests -- we don't really care about overwhelming our test API server
			QPS:   1000.0,
			Burst: 2000.0,
		},
	)
	if err != nil {
		t.Error(err)
	}

	kubeConfig, removeFile := createKubeConfigFile(t, testUser)

	kubeClientset, err := kubernetes.NewForConfig(env.Config)
	if err != nil {
		t.Error(err)
	}

	return &TestInstallApiServer{
			environment: env,
			testUser:    testUser,

			kubeClient: kubeClientset,

			kubeConfig: kubeConfig,
		}, func() {
			defer removeFile()
			stopFn()
		}
}

func createKubeConfigFile(t *testing.T, user *envtest.AuthenticatedUser) (string, CleanupFunction) {
	tmpfile, err := os.CreateTemp("", "config")
	if err != nil {
		t.Fatal(err)
	}
	path := tmpfile.Name()

	contents, err := user.KubeConfig()
	if err != nil {
		os.Remove(path)
		t.Fatal(err)
	}
	if _, err := tmpfile.Write(contents); err != nil {
		tmpfile.Close()
		os.Remove(path)
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		os.Remove(path)
		t.Fatal(err)
	}

	return path, func() {
		os.Remove(path)
	}
}

func (s *TestInstallApiServer) KubeConfig() string {
	return s.kubeConfig
}
