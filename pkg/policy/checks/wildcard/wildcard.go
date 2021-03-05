/*
Copyright 2021 The cert-manager Authors.

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

package wildcard

func Subset(patterns, members []string) bool {
	for _, member := range members {
		if !Contains(patterns, member) {
			return false
		}
	}

	return true
}

func Contains(patterns []string, member string) bool {
	for _, pattern := range patterns {
		if Matchs(pattern, member) {
			return true
		}
	}

	return false
}

func Matchs(pattern, str string) bool {
	if len(pattern) == 0 {
		return len(str) == 0
	}

	if pattern == "*" {
		return true
	}

	return matchRunes([]rune(pattern), []rune(str))
}

func matchRunes(pattern, str []rune) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			return matchRunes(pattern[1:], str) || (len(str) > 0 && matchRunes(pattern, str[1:]))

		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		}
		str = str[1:]
		pattern = pattern[1:]
	}
	return len(str) == 0 && len(pattern) == 0
}
