package mocks

import (
	"time"

	"github.com/golang/mock/gomock"
)

func DummySecret(c *gomock.Controller, validTill time.Time, domains []string) *MockSecret {
	mockSec := NewMockSecret(c)
	return mockSec
}
