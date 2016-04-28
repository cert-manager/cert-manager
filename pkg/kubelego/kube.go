package kubelego

import (
	"errors"
	"reflect"
	"strings"

	"github.com/simonswine/kube-lego/pkg/ingress"

	k8sApi "k8s.io/kubernetes/pkg/api"
	k8sExtensions "k8s.io/kubernetes/pkg/apis/extensions"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/util"
	"fmt"
)

func (kl *KubeLego) InitKube() error {

	// Try in cluster client first
	kubeClient, err := client.NewInCluster()
	if err != nil {
		kl.Log().Warnf("failed to create in-cluster client: %v.", err)

		// fall back to 127.0.0.1:8080 for dev
		kubeClient, err = client.New(
			&client.Config{
				Host: "127.0.0.1:8080",
			},
		)
		if err != nil {
			kl.Log().Warnf("failed to create test cluster client: %v.", err)
			return errors.New("kube init failed as both in-cluster and dev connection unavailable")
		}
	}

	kl.kubeClient = kubeClient
	return nil
}

func (kl *KubeLego) Namespace() string {
	return kl.LegoNamespace
}

func (kl *KubeLego) WatchConfig() {

	oldList := &k8sExtensions.IngressList{}

	rateLimiter := util.NewTokenBucketRateLimiter(0.1, 1)

	ingClient := kl.kubeClient.Extensions().Ingress(k8sApi.NamespaceAll)

	for {
		rateLimiter.Accept()

		list, err := ingClient.List(k8sApi.ListOptions{})
		if err != nil {
			kl.Log().Warn("Error while retrieving ingress list: ", err)
			continue
		}

		if reflect.DeepEqual(oldList, list) {
			continue
		}
		oldList = list

		kl.Reconfigure()

	}

}


func (kl *KubeLego) IngressProcess() []error {
	errs := []error{}
	/*for _, ing := range kl.legoIngressSlice {
		err := ing.Process()
		if err != nil {
			errs = append(errs, err)
		}
	}
	*/
	return errs
}


func (kl *KubeLego) UpdateChallengeEndpoints() error {

	/*
	domains := kl.IngressDomains()
	if len(domains) == 0 {
		kl.Log().Info("No update of challenge endpoints needed: no domains found")
		return nil
	}

	ing := ingress.New(kl, kl.LegoNamespace, kl.LegoIngressName)
	ing.IngressApi.Annotations = map[string]string{
		kubelego.AnnotationIngressChallengeEndpoints: "true",
	}

	// build ingress rules
	ing.IngressApi.Spec = kl.challengeIngressSpec(domains)

	// persist ingress rules in k8s
	return ing.Save()
	*/
	return nil
}

func (kl *KubeLego) Reconfigure() error {
	ingressesAll, err :=ingress.All(kl)
	if err != nil {
		return err
	}

	kl.legoIngressSlice = []*ingress.Ingress{}
	for _, ing := range ingressesAll{
		if ing.Ignore() {
			continue
		}
		kl.legoIngressSlice = append(kl.legoIngressSlice, ing)
	}

	kl.Log().Info("update challenge endpoint ingress, if needed")
	err = kl.UpdateChallengeEndpoints()
	if err != nil {
		kl.Log().Fatal("Error while updating challenge endpoints ingress: ", err)
	}

	kl.Log().Info("process certificates requests for ingresses")
	errs := kl.IngressProcess()
	if len(errs) > 0 {
		errsStr := []string{}
		for _, err := range errs {
			errsStr = append(errsStr, fmt.Sprintf("%s", err))
		}
		kl.Log().Fatal("Error while process certificate requests: ", strings.Join(errsStr, ", "))
	}

	return nil
}
