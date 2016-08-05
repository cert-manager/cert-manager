package mocks

import (
	"github.com/golang/mock/gomock"
	. "github.com/jetstack/kube-lego/pkg/kubelego_const"
)

func DummyTls(c *gomock.Controller, domainsSlice [][]string) (mockTlsSlice []Tls) {
	for _, domains := range domainsSlice {
		m := NewMockTls(c)
		m.EXPECT().Hosts().AnyTimes().Return(domains)
		mockTlsSlice = append(mockTlsSlice, m)
	}
	return
}

func DummyTlsDomain2(c *gomock.Controller) []Tls {
	return DummyTls(
		c,
		[][]string{
			[]string{"domain2"},
		},
	)
}

func DummyTlsDomain134(c *gomock.Controller) []Tls {
	return DummyTls(
		c,
		[][]string{
			[]string{"domain1"},
			[]string{"domain3", "domain4"},
		},
	)
}

func DummyTlsEmpty(c *gomock.Controller) []Tls {
	return DummyTls(
		c,
		[][]string{},
	)
}
