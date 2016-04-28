package utils

import (
	"strings"
	"sort"
	"crypto/md5"
	"fmt"
	"encoding/binary"
	"bytes"
)

func StringSliceLowerCase(in []string)[]string{
	out := []string{}
	for _, elem := range in {
		out = append(out, strings.ToLower(elem))
	}
	return out
}

func StringSliceDistinct(in []string) []string{
	elemMap := map[string]bool{}
	for _, elem := range in {
		elemMap[elem] = true
	}

	out:= []string{}
	for elem, _ := range elemMap {
		out = append(out, elem)
	}
	return out
}

func HashStringSlice(in []string) string{
	sort.Strings(in)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, in)

	return fmt.Sprintf("%x", md5.Sum(buf.Bytes()))
}