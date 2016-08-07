package mocks

import (
	"github.com/golang/mock/gomock"
)

func DummyService(c *gomock.Controller) *MockService{
	m := NewMockService(c)
	m.EXPECT().Save().AnyTimes().Return(nil)
	m.EXPECT().SetKubeLegoSpec().AnyTimes()
	m.EXPECT().Delete().AnyTimes().Return(nil)
	return m
}
