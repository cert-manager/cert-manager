/*
Copyright 2018 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"fmt"
	"sync"
)

// StringFilterT is a tuple for a value that has not been filtered out
type StringFilterT struct {
	String string
	Err    error
}

type StringFilterWrapper []StringFilterT

func (f StringFilterWrapper) Error() error {
	var errs []error
	for _, r := range f {
		if r.Err != nil {
			errs = append(errs, fmt.Errorf("'%s': %s", r.String, r.Err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

// FilterFn is a function used to filter a list of string. If the
// function returns false or a non-nil error, it will not be filtered.
type FilterFn func(string) (filter bool, err error)

// StringFilter will run fn with each element of in, filtering out elements.
// it will return a slice of results where fn returned ok, or a non-nil error.
// it will also call each instance of fn in it's own goroutine.
func StringFilter(fn FilterFn, in ...string) StringFilterWrapper {
	outCh := make(chan StringFilterT, len(in))
	var wg sync.WaitGroup
	for i, s := range in {
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			if filter, err := fn(s); err != nil || !filter {
				outCh <- StringFilterT{s, err}
			}
		}(i, s)
	}
	wg.Wait()
	close(outCh)
	res := make([]StringFilterT, len(outCh))
	i := 0
	for o := range outCh {
		res[i] = o
		i++
	}
	return res
}

func RemoveDuplicates(in []string) []string {
	var found []string
Outer:
	for _, i := range in {
		for _, i2 := range found {
			if i2 == i {
				continue Outer
			}
		}
		found = append(found, i)
	}
	return found
}
