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

package util

import (
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type Reporter struct {
	log      logr.Logger
	cr       *v1alpha1.CertificateRequest
	recorder record.EventRecorder
}

func NewReporter(log logr.Logger, cr *v1alpha1.CertificateRequest, recorder record.EventRecorder) *Reporter {
	return &Reporter{
		log:      log,
		cr:       cr,
		recorder: recorder,
	}
}

func (r *Reporter) WithLog(log logr.Logger) *Reporter {
	r.log = log
	return r
}

func (r *Reporter) Failed(err error, reason, message string) {
	r.recorder.Event(r.cr, corev1.EventTypeWarning, reason, fmt.Sprintf("%s: %v", message, err))
	r.log.Error(err, message)
	apiutil.SetCertificateRequestCondition(r.cr, v1alpha1.CertificateRequestReasonFailed, v1alpha1.ConditionFalse, reason, message)
}

func (r *Reporter) Pending(err error, reason, message string) {
	r.recorder.Event(r.cr, corev1.EventTypeNormal, reason, fmt.Sprintf("%s: %v", message, err))
	r.log.Error(err, message)
	apiutil.SetCertificateRequestCondition(r.cr, v1alpha1.CertificateRequestReasonPending, v1alpha1.ConditionFalse, reason, message)
}
