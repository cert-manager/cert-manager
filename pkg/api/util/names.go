/*
Copyright 2020 The cert-manager Authors.

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
	"encoding/json"
	"fmt"
	"hash/fnv"

	"regexp"
)

// ComputeName hashes the given object and prefixes it with prefix.
// The algorithm in use is Fowler–Noll–Vo hash function and is not
// cryptographically secure. Using a cryptographically secure hash is
// not necessary.
func ComputeName(prefix string, obj interface{}) (string, error) {
	objectBytes, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}

	hashF := fnv.New32()
	_, err = hashF.Write(objectBytes)
	if err != nil {
		return "", err
	}

	// we're shortening to stay under 64 as we use this in services
	// and pods down the road for ACME resources.
	prefix = DNSSafeShortenTo52Characters(prefix)

	return fmt.Sprintf("%s-%d", prefix, hashF.Sum32()), nil
}

// DNSSafeShortenTo52Characters shortens the input string to 52 chars and ensures the last char is an alpha-numeric character.
func DNSSafeShortenTo52Characters(in string) string {
	if len(in) >= 52 {
		validCharIndexes := regexp.MustCompile(`[a-zA-Z\d]`).FindAllStringIndex(fmt.Sprintf("%.52s", in), -1)
		in = in[:validCharIndexes[len(validCharIndexes)-1][1]]
	}

	return in
}
