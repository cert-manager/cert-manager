package util

import (
	"math/rand"
	"sort"
	"time"
)

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
	copy(s1_2, s1)
	copy(s2_2, s2)
	sort.Strings(s1_2)
	sort.Strings(s2_2)
	for i, s := range s1_2 {
		if s != s2_2[i] {
			return false
		}
	}
	return true
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// Contains returns true if a string is contained in a string slice
func Contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
