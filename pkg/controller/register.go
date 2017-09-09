package controller

type Interface func(workers int, stopCh <-chan struct{}) error
type Constructor func(ctx *Context) Interface

var (
	known = make(map[string]Constructor, 0)
)

func Known() map[string]Constructor {
	return known
}

func Register(name string, fn Constructor) {
	known[name] = fn
}
