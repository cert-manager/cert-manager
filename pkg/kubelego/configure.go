package kubelego

import (
	"github.com/simonswine/kube-lego/pkg/kubelego_const"
	"github.com/simonswine/kube-lego/pkg/utils"

	"fmt"
	"strings"
	"github.com/simonswine/kube-lego/pkg/ingress"
)


func (kl *KubeLego) TlsIgnoreDuplicatedSecrets(tlsSlice []kubelego.Tls) []kubelego.Tls {

	tlsBySecert := map[string][]kubelego.Tls{}

	for _, elm := range tlsSlice{
		key := fmt.Sprintf(
			"%s/%s",
			elm.SecretMetadata().Name,
			elm.SecretMetadata().Namespace,
		)
		tlsBySecert[key] = append(
			tlsBySecert[key],
			elm,
		)
	}

	output := []kubelego.Tls{}
	for key, slice := range tlsBySecert {
		if len(slice) == 1 {
			output = append(output, slice...)
			continue
		}

		texts := []string{}
		for _, elem := range slice {
			texts = append(
				texts,
				fmt.Sprintf(
					"ingress %s/%s (hosts: %s)",
					elem.IngressMetadata().Namespace,
					elem.IngressMetadata().Name,
					strings.Join(elem.Hosts(), ", "),
				),
			)
		}
		kl.Log().Warnf(
			"the secret %s is used multiple times. These linked TLS ingress elements where ignored: %s",
			key,
			strings.Join(texts, ", "),
		)
	}

	return output
}

func (kl *KubeLego) TlsAggregateHosts(tlsSlice []kubelego.Tls) []string {
	domains := []string{}
	for _, elem := range tlsSlice {
		domains = append(domains, elem.Hosts()...)
	}

	return utils.StringSliceDistinct(
	utils.StringSliceLowerCase(
		domains,
	),
	)
}

func (kl *KubeLego) Reconfigure() error {
	ingressesAll, err :=ingress.All(kl)
	if err != nil {
		return err
	}

	tlsSlice := []kubelego.Tls{}
	for _, ing := range ingressesAll{
		if ing.Ignore() {
			continue
		}
		tlsSlice = append(tlsSlice, ing.Tls()[0])
	}

	// normify tls config
	tlsSlice = kl.TlsIgnoreDuplicatedSecrets(tlsSlice)

	// get tls hostnames
	tlsHosts := kl.TlsAggregateHosts(tlsSlice)

	kl.Log().Info("update challenge endpoint ingress, if needed")
	err = kl.UpdateChallengeEndpoints(tlsHosts)
	if err != nil {
		kl.Log().Fatal("Error while updating challenge endpoints ingress: ", err)
	}

	kl.Log().Info("process certificates requests for ingresses")
	errs := kl.TlsProcessHosts(tlsSlice)
	if len(errs) > 0 {
		errsStr := []string{}
		for _, err := range errs {
			errsStr = append(errsStr, fmt.Sprintf("%s", err))
		}
		kl.Log().Fatal("Error while process certificate requests: ", strings.Join(errsStr, ", "))
	}

	return nil
}

func (kl *KubeLego) UpdateChallengeEndpoints(tlsHosts []string) error {

	hashNew := utils.HashStringSlice(tlsHosts)

	ing := ingress.New(kl, kl.LegoNamespace, kl.LegoIngressName)
	hashOld, ok := ing.IngressApi.Annotations[kubelego.AnnotationIngressChallengeEndpointsHash]

	if ok && hashNew == hashOld {
		kl.Log().Infof("challenge endpoints don't need a update")
		return nil
	}

	// build ingress rules
	ing.SetChallengeEndpoints(
		tlsHosts,
		kl.LegoServiceName,
		kl.legoHTTPPort,
	)

	// store hash
	ing.IngressApi.Annotations[kubelego.AnnotationIngressChallengeEndpointsHash] = hashNew

	// persist ingress rules in k8s
	return ing.Save()
}


func (kl *KubeLego) TlsProcessHosts(tlsSlice []kubelego.Tls) []error {
	errs := []error{}
	for _, tlsElem := range tlsSlice {
		err := tlsElem.Process()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}


