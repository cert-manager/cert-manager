package controller

var (
	known = make(map[string]InitFn, 0)
)

func Known() map[string]InitFn {
	return known
}

func Register(name string, fn InitFn) {
	known[name] = fn
}
