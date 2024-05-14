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

package v1alpha1

import (
	"time"

	conversion "k8s.io/apimachinery/pkg/conversion"

	shared "github.com/cert-manager/cert-manager/internal/apis/config/shared"
	"github.com/cert-manager/cert-manager/pkg/apis/config/shared/v1alpha1"
)

// Convert_shared_TLSConfig_To_v1alpha1_TLSConfig is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_shared_TLSConfig_To_v1alpha1_TLSConfig(in *shared.TLSConfig, out *v1alpha1.TLSConfig, s conversion.Scope) error {
	return autoConvert_shared_TLSConfig_To_v1alpha1_TLSConfig(in, out, s)
}

// Convert_v1alpha1_TLSConfig_To_shared_TLSConfig is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_v1alpha1_TLSConfig_To_shared_TLSConfig(in *v1alpha1.TLSConfig, out *shared.TLSConfig, s conversion.Scope) error {
	return autoConvert_v1alpha1_TLSConfig_To_shared_TLSConfig(in, out, s)
}

// Convert_shared_LeaderElectionConfig_To_v1alpha1_LeaderElectionConfig is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_shared_LeaderElectionConfig_To_v1alpha1_LeaderElectionConfig(in *shared.LeaderElectionConfig, out *v1alpha1.LeaderElectionConfig, s conversion.Scope) error {
	return autoConvert_shared_LeaderElectionConfig_To_v1alpha1_LeaderElectionConfig(in, out, s)
}

// Convert_v1alpha1_LeaderElectionConfig_To_shared_LeaderElectionConfig is explicitly defined to avoid issues in conversion-gen
// when referencing types in other API groups.
func Convert_v1alpha1_LeaderElectionConfig_To_shared_LeaderElectionConfig(in *v1alpha1.LeaderElectionConfig, out *shared.LeaderElectionConfig, s conversion.Scope) error {
	return autoConvert_v1alpha1_LeaderElectionConfig_To_shared_LeaderElectionConfig(in, out, s)
}

func Convert_Pointer_float32_To_float32(in **float32, out *float32, s conversion.Scope) error {
	if *in == nil {
		*out = 0
		return nil
	}
	*out = float32(**in)
	return nil
}

func Convert_float32_To_Pointer_float32(in *float32, out **float32, s conversion.Scope) error {
	temp := float32(*in)
	*out = &temp
	return nil
}

func Convert_Pointer_int32_To_int(in **int32, out *int, s conversion.Scope) error {
	if *in == nil {
		*out = 0
		return nil
	}
	*out = int(**in)
	return nil
}

func Convert_int_To_Pointer_int32(in *int, out **int32, s conversion.Scope) error {
	temp := int32(*in)
	*out = &temp
	return nil
}

func Convert_Pointer_v1alpha1_Duration_To_time_Duration(in **v1alpha1.Duration, out *time.Duration, s conversion.Scope) error {
	if *in == nil {
		*out = 0
		return nil
	}
	*out = (*in).Duration.Duration
	return nil
}

func Convert_time_Duration_To_Pointer_v1alpha1_Duration(in *time.Duration, out **v1alpha1.Duration, s conversion.Scope) error {
	*out = v1alpha1.DurationFromTime(*in)
	return nil
}
