package gce

import (
	"testing"

	"github.com/jetstack/kube-lego/pkg/mocks"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	k8sExtensions "k8s.io/kubernetes/pkg/apis/extensions"
)

func TestGce(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Gce Suite")
}

var _ = Describe("Gce", func() {
	var (
		provider *Gce
		ctrlMock *gomock.Controller
		mockIng  *mocks.MockIngress
		ing      *k8sExtensions.Ingress
		mockKl   *mocks.MockKubeLego
	)

	BeforeEach(func() {
		ctrlMock = gomock.NewController(GinkgoT())
		defer ctrlMock.Finish()

		mockKl = mocks.DummyKubeLego(ctrlMock)

		provider = New(mockKl)
	})

	Describe("ProcessIngress", func() {
		Context("Ingress with no rules but TLS hosts", func() {
			BeforeEach(func() {
				mockIng = mocks.DummyIngressNoRulesTLSDomains134(ctrlMock)
				ing = mockIng.Ingress()
			})
			It("should add rules for the hosts", func() {
				provider.ProcessIngress(mockIng)
				Expect(len(ing.Spec.Rules)).To(Equal(3))
				for _, rule := range ing.Spec.Rules {
					Expect(rule.Host[:len(rule.Host)-1]).To(Equal("domain"))
					Expect(rule.HTTP.Paths[0].Path).To(Equal("/.well-known/acme-challenge/*"))
					Expect(rule.HTTP.Paths[0].Backend).To(Equal(mocks.BasicIngressBackend("kube-lego-gce", 8080)))

				}
			})
			It("should add challenge paths only once", func() {
				provider.ProcessIngress(mockIng)
				provider.ProcessIngress(mockIng)
				Expect(len(ing.Spec.Rules)).To(Equal(3))
				for _, rule := range ing.Spec.Rules {
					Expect(len(rule.HTTP.Paths)).To(Equal(1))
				}
			})
			It("should mark namespace as used", func() {
				provider.ProcessIngress(mockIng)
				Expect(provider.usedByNamespace).To(HaveKeyWithValue(ing.ObjectMeta.Namespace, true))
			})
		})
		Context("Ingress with with challenge rules domain12 and no tls", func() {
			BeforeEach(func() {
				mockIng = mocks.DummyIngressDomain12Challenge12(ctrlMock, mocks.DummyTlsEmpty(ctrlMock))
				ing = mockIng.Ingress()
			})
			It("should remove challenge rules for the hosts", func() {
				provider.ProcessIngress(mockIng)
				Expect(len(ing.Spec.Rules)).To(Equal(2))
				for _, rule := range ing.Spec.Rules {
					Expect(len(rule.HTTP.Paths)).To(Equal(1))
					Expect(rule.HTTP.Paths[0].Path).To(Not(Equal("/.well-known/acme-challenge/*")))
				}
			})
			It("should not mark namespace as used", func() {
				provider.ProcessIngress(mockIng)
				Expect(provider.usedByNamespace).To(Not(HaveKeyWithValue(ing.ObjectMeta.Namespace, true)))
			})
		})
		Context("Ingress without challenge rules on domains12 and tls on domain134", func() {
			BeforeEach(func() {
				mockIng = mocks.DummyIngressDomain12(ctrlMock, mocks.DummyTlsDomain2(ctrlMock))
				ing = mockIng.Ingress()
			})
			It("should add challenge rules for the host domain2", func() {
				provider.ProcessIngress(mockIng)
				Expect(len(ing.Spec.Rules)).To(Equal(2))
				for _, rule := range ing.Spec.Rules {
					if rule.Host == "domain1" {
						Expect(len(rule.HTTP.Paths)).To(Equal(1))
						Expect(rule.HTTP.Paths[0].Path).To(Not(Equal("/.well-known/acme-challenge/*")))
					}
					if rule.Host == "domain2" {
						Expect(len(rule.HTTP.Paths)).To(Equal(2))
						Expect(rule.HTTP.Paths[0].Path).To(Equal("/.well-known/acme-challenge/*"))
						Expect(rule.HTTP.Paths[1].Path).To(Not(Equal("/.well-known/acme-challenge/*")))
					}
				}
			})
			It("should mark namespace as used", func() {
				provider.ProcessIngress(mockIng)
				Expect(provider.usedByNamespace).To(HaveKeyWithValue(ing.ObjectMeta.Namespace, true))
			})
		})
	})
})
