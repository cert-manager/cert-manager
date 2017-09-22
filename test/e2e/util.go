package e2e

import (
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewCertManagerControllerPod(name string, args ...string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app": name,
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:            name,
					Image:           certManagerImageFlag,
					Args:            args,
					ImagePullPolicy: v1.PullPolicy(certManagerImagePullPolicy),
				},
			},
		},
	}
}

func strPtr(s string) *string {
	return &s
}
