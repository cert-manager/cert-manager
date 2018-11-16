package exec

import "github.com/stretchr/testify/mock"

type LogRecorder struct {
	mock.Mock
}

func (*LogRecorder) Fatal(args ...interface{}) {
	panic("implement me")
}

func (*LogRecorder) Fatalln(args ...interface{}) {
	panic("implement me")
}

func (*LogRecorder) Fatalf(format string, args ...interface{}) {
	panic("implement me")
}

func (*LogRecorder) Print(args ...interface{}) {
	panic("implement me")
}

func (l *LogRecorder) Println(args ...interface{}) {
	l.Called(args...)
}

func (*LogRecorder) Printf(format string, args ...interface{}) {
	panic("implement me")
}
