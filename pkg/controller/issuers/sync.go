/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package issuers

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/errors"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/controller/issuers/internal/generic"
	internalapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/webhook"
)

const (
	errorInitIssuer = "ErrInitIssuer"
	errorConfig     = "ConfigError"

	messageErrorInitIssuer = "Error initializing issuer: "
)

func (c *controller) Sync(ctx context.Context, issuer cmapi.GenericIssuer) (err error) {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	if !c.issuerBackend.TypeChecker(issuer) {
		dbg.Info("issuer spec type does not match issuer backend so skipping processing")
		return nil
	}

	issuerCopy := issuer.Copy()
	defer func() {
		if _, saveErr := c.updateIssuerStatus(issuer, issuerCopy); saveErr != nil {
			err = errors.NewAggregate([]error{saveErr, err})
		}
	}()

	el := webhook.ValidationRegistry.Validate(issuerCopy, genericIssuerGvk(issuerCopy))
	if len(el) > 0 {
		msg := fmt.Sprintf("Resource validation failed: %v", el.ToAggregate())
		apiutil.SetIssuerCondition(issuerCopy, v1alpha2.IssuerConditionReady, cmmeta.ConditionFalse, errorConfig, msg)
		return
	}

	// Remove existing ErrorConfig condition if it exists
	status := issuerCopy.GetStatus()
	for i, c := range status.Conditions {
		if c.Type == v1alpha2.IssuerConditionReady {
			if c.Reason == errorConfig && c.Status == cmmeta.ConditionFalse {
				status.Conditions = append(status.Conditions[:i], status.Conditions[i+1:]...)
				break
			}
		}
	}
	issuerCopy.SetStatus(status)

	// allow a maximum of 10s
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	if err := c.issuerBackend.Setup(ctx, issuerCopy); err != nil {
		log.Error(err, errorInitIssuer)
		return err
	}

	return nil
}

func (c *controller) updateIssuerStatus(old, new cmapi.GenericIssuer) (cmapi.GenericIssuer, error) {
	if reflect.DeepEqual(old.GetStatus(), new.GetStatus()) {
		return nil, nil
	}
	return generic.Update(c.cmClient, new)
}

func genericIssuerGvk(issuer cmapi.GenericIssuer) schema.GroupVersionKind {
	return internalapi.SchemeGroupVersion.WithKind(issuer.GetObjectKind().GroupVersionKind().Kind)
}
