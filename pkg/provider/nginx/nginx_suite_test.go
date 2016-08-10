package nginx

import (
	"testing"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"github.com/jetstack/kube-lego/pkg/mocks"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	k8sApi "k8s.io/kubernetes/pkg/api"
	k8sExtensions "k8s.io/kubernetes/pkg/apis/extensions"
)

func TestNginx(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Nginx Suite")
}

var _ = Describe("Nginx", func() {
	var (
		provider *Nginx
		ctrlMock *gomock.Controller
		mockIng  *mocks.MockIngress
		mockSvc  *mocks.MockService
		ing      *k8sExtensions.Ingress
		mockTls  []kubelego.Tls
		mockKl   *mocks.MockKubeLego
	)

	BeforeEach(func() {
		ctrlMock = gomock.NewController(GinkgoT())
		defer ctrlMock.Finish()

		mockKl = mocks.DummyKubeLego(ctrlMock)

		provider = New(mockKl)
	})

	Describe("Process", func() {
		Context("Ingress with no TLS hosts", func() {
			BeforeEach(func() {
				mockTls = mocks.DummyTlsEmpty(ctrlMock)
				mockIng = mocks.DummyIngressDomain1(ctrlMock, mockTls)
				ing = mockIng.Object()
			})
			It("should not fail", func() {
				provider.Process(mockIng)
			})
			It("should not change host map", func() {
				hostsBefore := provider.hosts
				provider.Process(mockIng)
				Expect(hostsBefore).To(Equal(provider.hosts))
			})
		})
		Context("Ingress with TLS hosts", func() {
			BeforeEach(func() {
				mockTls = mocks.DummyTlsDomain134(ctrlMock)
				mockIng = mocks.DummyIngressDomain1(ctrlMock, mockTls)
				ing = mockIng.Object()
			})
			It("should not fail", func() {
				provider.Process(mockIng)
			})
			It("should add the three domains to the host", func() {
				count := len(provider.hosts)
				provider.Process(mockIng)
				Expect(len(provider.hosts)).To(Equal(count + 3))
			})
			It("should not append more hosts on duplicates", func() {
				count := len(provider.hosts)
				provider.Process(mockIng)
				Expect(len(provider.hosts)).To(Equal(count + 3))
				provider.Process(mockIng)
				Expect(len(provider.hosts)).To(Equal(count + 3))
			})
			It("should add domains 1,3,4", func() {
				provider.Process(mockIng)
				for _, domain := range []string{"domain1", "domain3", "domain4"} {
					value, ok := provider.hosts[domain]
					Expect(value && ok).To(Equal(true))
				}
			})
		})
	})
	Describe("Finalize", func() {
		BeforeEach(func() {
			ing = &k8sExtensions.Ingress{
				ObjectMeta: k8sApi.ObjectMeta{
					Name:      "kube-lego-nginx",
					Namespace: "kube-lego",
				},
			}
			mockIng = mocks.NewMockIngress(ctrlMock)
			provider.ingress = mockIng

			mockSvc = mocks.NewMockService(ctrlMock)
			provider.service = mockSvc
		})
		Context("no tls hosts", func() {
			BeforeEach(func() {
			})
			It("should remove existing service/ingress object", func() {
				mockIng.EXPECT().Delete().MinTimes(1).Return(nil)
				mockSvc.EXPECT().Delete().MinTimes(1).Return(nil)
				provider.Finalize()
			})
		})
		Context("with tls hosts", func() {
			BeforeEach(func() {
				provider.hosts = map[string]bool{
					"domain1": true,
					"domain3": true,
					"domain4": true,
				}
				mockSvc.EXPECT().SetKubeLegoSpec().AnyTimes()
				mockIng.EXPECT().Object().AnyTimes().Return(ing)
			})
			It("should update ingress/service", func() {
				mockIng.EXPECT().Save().MinTimes(1).Return(nil)
				mockSvc.EXPECT().Save().MinTimes(1).Return(nil)
				provider.Finalize()
			})
			It("should update challenge endpoints", func() {
				mockIng.EXPECT().Save().AnyTimes().Return(nil)
				mockSvc.EXPECT().Save().AnyTimes().Return(nil)
				provider.Finalize()
				Expect(len(ing.Spec.Rules)).To(Equal(3))
			})
		})
	})
})
