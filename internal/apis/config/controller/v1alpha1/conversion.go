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
	controller "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	v1alpha1 "github.com/cert-manager/cert-manager/pkg/apis/config/controller/v1alpha1"
	conversion "k8s.io/apimachinery/pkg/conversion"
	"k8s.io/component-base/logs"
	logsapi "k8s.io/component-base/logs/api/v1"
)

func Convert_v1alpha1_ControllerConfiguration_To_controller_ControllerConfiguration(in *v1alpha1.ControllerConfiguration, out *controller.ControllerConfiguration, s conversion.Scope) error {
	if err := autoConvert_v1alpha1_ControllerConfiguration_To_controller_ControllerConfiguration(in, out, s); err != nil {
		return err
	}
	return nil
}

func Convert_controller_ControllerConfiguration_To_v1alpha1_ControllerConfiguration(in *controller.ControllerConfiguration, out *v1alpha1.ControllerConfiguration, s conversion.Scope) error {
	if err := autoConvert_controller_ControllerConfiguration_To_v1alpha1_ControllerConfiguration(in, out, s); err != nil {
		return err
	}
	return nil
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

func Convert_Pointer_v1_LoggingConfiguration_To_v1_LoggingConfiguration(in **logsapi.LoggingConfiguration, out *logsapi.LoggingConfiguration, s conversion.Scope) error {
	if *in == nil {
		temp := logs.NewOptions()
		temp.DeepCopyInto(out)
		return nil
	}
	(*in).DeepCopyInto(out)
	return nil
}

func Convert_v1_LoggingConfiguration_To_Pointer_v1_LoggingConfiguration(in *logsapi.LoggingConfiguration, out **logsapi.LoggingConfiguration, s conversion.Scope) error {
	temp := in.DeepCopy()
	*out = temp
	return nil
}
