package util

import "sort"

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

func EqualUnsorted(s1 []string, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}
	s1_2, s2_2 := make([]string, len(s1)), make([]string, len(s2))
	sort.Strings(s1)
	sort.Strings(s2)
	for i, s := range s1_2 {
		if s != s2_2[i] {
			return false
		}
	}
	return true
}
