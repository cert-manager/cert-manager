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

package challengepayload

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/jetstack/cert-manager/pkg/acme/webhook"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
)

type REST struct {
	hookFn webhook.Solver
}

var _ rest.Creater = &REST{}
var _ rest.Scoper = &REST{}
var _ rest.GroupVersionKindProvider = &REST{}

func NewREST(hookFn webhook.Solver) *REST {
	return &REST{
		hookFn: hookFn,
	}
}

func (r *REST) New() runtime.Object {
	return &v1alpha1.ChallengePayload{}
}

func (r *REST) GroupVersionKind(containingGV schema.GroupVersion) schema.GroupVersionKind {
	return v1alpha1.SchemeGroupVersion.WithKind("ChallengePayload")
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	payload, ok := obj.(*v1alpha1.ChallengePayload)
	if !ok {
		return nil, fmt.Errorf("resource is not of type ChallengePayload")
	}
	if payload.Request == nil {
		return nil, fmt.Errorf("payload request field cannot be empty")
	}
	resp, err := r.callSolver(*payload.Request)
	if err != nil {
		return nil, err
	}
	payload.Response = &resp
	return payload, nil
}

// callSolver will call the appropriate method on the REST handlers Solver.
// It will only return an error if setting up the solver fails.
func (r *REST) callSolver(req v1alpha1.ChallengeRequest) (v1alpha1.ChallengeResponse, error) {
	var fn func(*v1alpha1.ChallengeRequest) error
	switch req.Action {
	case v1alpha1.ChallengeActionPresent:
		fn = r.hookFn.Present
	case v1alpha1.ChallengeActionCleanUp:
		fn = r.hookFn.CleanUp
	default:
		return v1alpha1.ChallengeResponse{}, fmt.Errorf("unknown action type %q", req.Action)
	}
	err := fn(&req)
	if err == nil {
		return v1alpha1.ChallengeResponse{
			UID:     req.UID,
			Success: true,
		}, nil
	}

	return v1alpha1.ChallengeResponse{
		UID: req.UID,
		Result: &metav1.Status{
			Status:  "Failed",
			Message: err.Error(),
			// TODO: utilise Reason field etc.
		},
	}, nil
}
