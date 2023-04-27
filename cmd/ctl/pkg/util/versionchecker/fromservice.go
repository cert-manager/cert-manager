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

package versionchecker

import (
	"context"
	"regexp"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var imageVersion = regexp.MustCompile(`^quay.io/jetstack/cert-manager-webhook:(v(?:\d+)\.(?:\d+)\.(?:\d+)(?:.*))$`)

func (o *VersionChecker) extractVersionFromService(
	ctx context.Context,
	namespace string,
	serviceName string,
) error {
	service := &corev1.Service{}
	serviceKey := client.ObjectKey{Namespace: namespace, Name: serviceName}
	err := o.client.Get(ctx, serviceKey, service)
	if err != nil {
		return err
	}

	if label := extractVersionFromLabels(service.Labels); label != "" {
		o.versionSources["webhookServiceLabelVersion"] = label
	}

	listOptions := client.MatchingLabelsSelector{
		Selector: labels.Set(service.Spec.Selector).AsSelector(),
	}
	pods := &corev1.PodList{}
	err = o.client.List(ctx, pods, listOptions)
	if err != nil {
		return err
	}

	for _, pod := range pods.Items {
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}

		if label := extractVersionFromLabels(pod.Labels); label != "" {
			o.versionSources["webhookPodLabelVersion"] = label
		}

		for _, container := range pod.Spec.Containers {
			version := imageVersion.FindStringSubmatch(container.Image)
			if len(version) == 2 {
				o.versionSources["webhookPodImageVersion"] = version[1]
				return nil
			}
		}
	}

	return nil
}
