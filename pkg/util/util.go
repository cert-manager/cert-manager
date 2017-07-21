package util

func OnlyOneNotNil(items ...interface{}) (any bool, one bool) {
	oneNotNil := false
	for _, i := range items {
		if i != nil {
			if oneNotNil {
				return true, false
			}
			oneNotNil = true
		}
	}
	return oneNotNil, oneNotNil
}
